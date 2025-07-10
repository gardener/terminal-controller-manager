/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	kErros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/yaml"

	extensionsv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
	"github.com/gardener/terminal-controller-manager/internal/utils"
)

// TerminalReconciler reconciles a Terminal object
type TerminalReconciler struct {
	Scheme *runtime.Scheme
	*gardenclient.ClientSet
	Recorder                    record.EventRecorder
	Config                      *extensionsv1alpha1.ControllerManagerConfiguration
	ReconcilerCountPerNamespace map[string]int
	mutex                       sync.RWMutex
	configMutex                 sync.RWMutex
}

func (r *TerminalReconciler) SetupWithManager(mgr ctrl.Manager, config extensionsv1alpha1.TerminalControllerConfiguration) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha1.Terminal{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Reconcile on spec changes
				if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
					return true
				}

				if !reflect.DeepEqual(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations()) {
					return true
				}

				if !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) {
					return true
				}

				return false
			},
		})).
		Named("main").
		WithOptions(controller.Options{
			MaxConcurrentReconciles: config.MaxConcurrentReconciles,
		}).
		Complete(r)
}

func (r *TerminalReconciler) getConfig() *extensionsv1alpha1.ControllerManagerConfiguration {
	r.configMutex.RLock()
	defer r.configMutex.RUnlock()

	return r.Config
}

// Mainly used for tests to inject config
func (r *TerminalReconciler) injectConfig(config *extensionsv1alpha1.ControllerManagerConfiguration) {
	r.configMutex.Lock()
	defer r.configMutex.Unlock()

	r.Config = config
}

func (r *TerminalReconciler) increaseCounterForNamespace(namespace string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var counter int
	if c, exists := r.ReconcilerCountPerNamespace[namespace]; !exists {
		counter = 1
	} else {
		counter = c + 1
	}

	if counter > r.getConfig().Controllers.Terminal.MaxConcurrentReconcilesPerNamespace {
		return errors.New("max count reached")
	}

	r.ReconcilerCountPerNamespace[namespace] = counter

	return nil
}

func (r *TerminalReconciler) decreaseCounterForNamespace(namespace string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var counter int

	c, exists := r.ReconcilerCountPerNamespace[namespace]
	if !exists {
		return
	}

	counter = c - 1
	if counter == 0 {
		delete(r.ReconcilerCountPerNamespace, namespace)
	} else {
		r.ReconcilerCountPerNamespace[namespace] = counter
	}
}

func (r *TerminalReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if err := r.increaseCounterForNamespace(req.Namespace); err != nil {
		log.FromContext(ctx).Info("maximum parallel reconciles reached for namespace - requeuing the req")

		return ctrl.Result{
			RequeueAfter: wait.Jitter(time.Duration(int64(100*time.Millisecond)), 50), // requeue after 100ms - 5s
		}, nil
	}

	res, err := r.handleRequest(ctx, req)

	r.decreaseCounterForNamespace(req.Namespace)

	return res, err
}

func (r *TerminalReconciler) handleRequest(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	t := &extensionsv1alpha1.Terminal{}

	err := r.Get(ctx, req.NamespacedName, t)
	if err != nil {
		if kErros.IsNotFound(err) {
			// Object not found, return. Created objects are automatically garbage collected.
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the req.
		return ctrl.Result{}, err
	}

	lastOperationType := extensionsv1alpha1.LastOperationTypeReconcile
	if !t.DeletionTimestamp.IsZero() {
		lastOperationType = extensionsv1alpha1.LastOperationTypeDelete
	}

	if updateErr := r.patchTerminalStatus(ctx, t, func(terminal *extensionsv1alpha1.Terminal) error {
		terminal.Status.LastOperation = reconcileProcessing(lastOperationType, "Reconciliation of Terminal initialized.")
		return nil
	}); updateErr != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update terminal status: %w", updateErr)
	}

	result, err := r.handleTerminal(ctx, t)

	if updateErr := r.patchTerminalStatus(ctx, t, func(terminal *extensionsv1alpha1.Terminal) error {
		if err != nil {
			terminal.Status.LastError = lastError(err.Error())
			terminal.Status.LastOperation = reconcileError(lastOperationType, err.Error())
		} else {
			terminal.Status.LastError = nil
			terminal.Status.LastOperation = reconcileSucceeded(lastOperationType, "Terminal has been successfully reconciled.")
		}
		return nil
	}); client.IgnoreNotFound(updateErr) != nil {
		return ctrl.Result{}, errors.Join(updateErr, err)
	}

	return result, err
}

func (r *TerminalReconciler) handleTerminal(ctx context.Context, t *extensionsv1alpha1.Terminal) (ctrl.Result, error) {
	gardenClientSet := r.ClientSet

	cfg := r.getConfig()

	hostClientSet, hostClientSetErr := gardenclient.NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Host.Credentials, cfg.HonourServiceAccountRefHostCluster, cfg.Controllers.Terminal.TokenRequestExpirationSeconds, r.Scheme)
	targetClientSet, targetClientSetErr := gardenclient.NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Target.Credentials, cfg.HonourServiceAccountRefTargetCluster, cfg.Controllers.Terminal.TokenRequestExpirationSeconds, r.Scheme)

	if !t.DeletionTimestamp.IsZero() {
		return r.deleteTerminal(ctx, t, hostClientSetErr, targetClientSetErr, targetClientSet, hostClientSet)
	}

	if hostClientSetErr != nil {
		if ok, cause := isResourceNoLongerAvailableError(hostClientSetErr); ok {
			r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError,
				"Host cluster credentials no longer available due to %s, deleting terminal: %s", cause, hostClientSetErr.Error())

			// Trigger deletion by deleting the terminal resource
			return r.deleteTerminalDueToMissingResources(ctx, t)
		}

		return ctrl.Result{}, hostClientSetErr
	}

	if targetClientSetErr != nil {
		if ok, cause := isResourceNoLongerAvailableError(targetClientSetErr); ok {
			r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError,
				"Target cluster credentials no longer available due to %s, deleting terminal: %s", cause, targetClientSetErr.Error())

			// Trigger deletion by deleting the terminal resource
			return r.deleteTerminalDueToMissingResources(ctx, t)
		}

		return ctrl.Result{}, targetClientSetErr
	}

	if err := r.ensureAdmissionWebhookConfigured(ctx, gardenClientSet, t); err != nil {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, "Failed ensuring admission webhook is configured: %s", err.Error())
		return ctrl.Result{}, err
	}

	if err := r.ensureFinalizer(ctx, t); err != nil {
		return ctrl.Result{}, err
	}

	labelSet, err := t.NewLabelsSet()
	if err != nil {
		// the needed labels will be set eventually, requeue won't change that
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, "Transient problem - %s. Skipping...", err.Error())

		return ctrl.Result{}, nil
	}

	annotationSet, err := t.NewAnnotationsSet()
	if err != nil {
		// the needed annotations will be set eventually, requeue won't change that
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, "Transient problem - %s. Skipping...", err.Error())

		return ctrl.Result{}, nil
	}

	r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventReconciling, "Reconciling Terminal state")

	if err = r.reconcileTerminal(ctx, targetClientSet, hostClientSet, t, labelSet, annotationSet); err != nil {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, "Failed reconciling Terminal state: %s", err.Error())
		return ctrl.Result{}, err
	}

	r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventReconciled, "Reconciled Terminal state")

	return ctrl.Result{}, nil
}

func (r *TerminalReconciler) ensureFinalizer(ctx context.Context, t *extensionsv1alpha1.Terminal) error {
	// fetch the latest version of the Terminal resource
	terminal := &extensionsv1alpha1.Terminal{}
	if err := r.Get(ctx, client.ObjectKey{Name: t.Name, Namespace: t.Namespace}, terminal); err != nil {
		return err
	}

	patch := client.MergeFrom(terminal.DeepCopy())

	finalizers := sets.NewString(terminal.Finalizers...)
	if finalizers.Has(extensionsv1alpha1.TerminalName) {
		// nothing to do
		return nil
	}

	finalizers.Insert(extensionsv1alpha1.TerminalName)
	terminal.Finalizers = finalizers.UnsortedList()

	return r.Patch(ctx, terminal, patch)
}

func (r *TerminalReconciler) removeFinalizer(ctx context.Context, t *extensionsv1alpha1.Terminal) error {
	// fetch the latest version of the Terminal before removing the finalizer
	terminal := &extensionsv1alpha1.Terminal{}
	if err := r.Get(ctx, client.ObjectKey{Name: t.Name, Namespace: t.Namespace}, terminal); err != nil {
		return err
	}

	patch := client.MergeFrom(terminal.DeepCopy())

	// remove our finalizer from the list and update it.
	controllerutil.RemoveFinalizer(terminal, extensionsv1alpha1.TerminalName)

	return r.Patch(ctx, terminal, patch)
}

func (r *TerminalReconciler) deleteTerminal(ctx context.Context, t *extensionsv1alpha1.Terminal, hostClientSetErr error, targetClientSetErr error, targetClientSet *gardenclient.ClientSet, hostClientSet *gardenclient.ClientSet) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(t, extensionsv1alpha1.TerminalName) {
		// Our finalizer has finished, so the reconciler can do nothing.
		return ctrl.Result{}, nil
	}

	// During deletion, ensure cleanup continues even if host or target cluster credentials are unavailable, e.g., if the corresponding cluster has been deleted.
	if hostClientSetErr != nil {
		if ok, cause := isResourceNoLongerAvailableError(hostClientSetErr); ok {
			r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventDeleting,
				"Host cluster credentials no longer available due to %s during deletion, continuing cleanup: %s", cause, hostClientSetErr.Error())
		} else {
			return ctrl.Result{}, hostClientSetErr
		}
	}

	if targetClientSetErr != nil {
		if ok, cause := isResourceNoLongerAvailableError(targetClientSetErr); ok {
			r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventDeleting,
				"Target cluster credentials no longer available due to %s during deletion, continuing cleanup: %s", cause, targetClientSetErr.Error())
		} else {
			return ctrl.Result{}, targetClientSetErr
		}
	}

	r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleting, "Deleting external dependencies")
	// our finalizer is present, so lets handle our external dependency

	if deletionErrors := r.deleteExternalDependency(ctx, targetClientSet, hostClientSet, t); deletionErrors != nil {
		var errStrings []string
		// if deletion of the external dependency fails, return with error so that it can be retried
		for _, deletionErr := range deletionErrors {
			r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventDeleteError, "Failed deleting external dependencies: %s", deletionErr.Error())
			errStrings = append(errStrings, deletionErr.Error())
		}

		return ctrl.Result{}, errors.New(strings.Join(errStrings, "\n"))
	}

	r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleted, "Deleted external dependencies")

	if err := r.removeFinalizer(ctx, t); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *TerminalReconciler) recordEventAndLog(ctx context.Context, t *extensionsv1alpha1.Terminal, eventType, reason, messageFmt string, args ...interface{}) {
	r.Recorder.Eventf(t, eventType, reason, messageFmt, args...)
	log.FromContext(ctx).Info(fmt.Sprintf(messageFmt, args...))
}

// isResourceNoLongerAvailableError checks if an error indicates that referenced resources
// (shoots, service accounts, or garden projects) no longer exist and the terminal should be deleted.
// This follows the same pattern used by Kubernetes core controllers.
// It returns true if the error matches, along with a string describing the specific cause.
func isResourceNoLongerAvailableError(err error) (bool, string) {
	if err == nil {
		return false, ""
	}

	if kErros.IsNotFound(err) {
		return true, "NotFound"
	}

	if kErros.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
		return true, "NamespaceTerminating"
	}

	return false, ""
}

// deleteTerminalDueToMissingResources triggers deletion of a terminal when referenced resources are no longer available.
func (r *TerminalReconciler) deleteTerminalDueToMissingResources(ctx context.Context, t *extensionsv1alpha1.Terminal) (ctrl.Result, error) {
	// Delete the terminal resource, which will trigger the normal deletion flow
	if err := r.Delete(ctx, t); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to delete terminal due to missing resources: %w", err)
	}

	// Return success - the deletion will be handled in the next reconcile cycle
	return ctrl.Result{}, nil
}

func (r *TerminalReconciler) ensureAdmissionWebhookConfigured(ctx context.Context, gardenClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	webhookConfigurationOptions := metav1.ListOptions{}
	webhookConfigurationOptions.LabelSelector = labels.SelectorFromSet(map[string]string{
		"app.kubernetes.io/name":      "terminal",
		"app.kubernetes.io/component": "admission-controller",
	}).String()

	mutatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
	if err != nil {
		return err
	}

	if len(mutatingWebhookConfigurations.Items) != 1 {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("expected 1 MutatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(mutatingWebhookConfigurations.Items))
	}

	mutatingWebhookConfiguration := mutatingWebhookConfigurations.Items[0]
	if mutatingWebhookConfiguration.CreationTimestamp.After(t.CreationTimestamp.Time) {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("terminal %s has been created before mutating webhook was configured. Deleting resource", t.Name)
	}

	validatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
	if err != nil {
		return err
	}

	if len(validatingWebhookConfigurations.Items) != 1 {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("expected 1 ValidatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(validatingWebhookConfigurations.Items))
	}

	validatingWebhookConfiguration := validatingWebhookConfigurations.Items[0]
	if validatingWebhookConfiguration.CreationTimestamp.After(t.CreationTimestamp.Time) {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("terminal %s has been created before validating webhook was configured. Deleting resource", t.Name)
	}

	return nil
}

// deleteExternalDependency deletes external dependencies on target and host cluster. In case of an error on the target cluster (e.g. api server cannot be reached) the dependencies on the host cluster are still tried to delete.
func (r *TerminalReconciler) deleteExternalDependency(ctx context.Context, targetClientSet *gardenclient.ClientSet, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) []error {
	var lastErrors []error

	if targetErr := r.deleteTargetClusterDependencies(ctx, targetClientSet, t); targetErr != nil {
		lastErrors = append(lastErrors, targetErr)
	}

	if hostErr := r.deleteHostClusterDependencies(ctx, hostClientSet, t); hostErr != nil {
		lastErrors = append(lastErrors, hostErr)
	}

	if len(lastErrors) >= 0 {
		return lastErrors
	}

	return nil
}

func (r *TerminalReconciler) deleteTargetClusterDependencies(ctx context.Context, targetClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	if targetClientSet != nil {
		if err := r.deleteAccessToken(ctx, targetClientSet, t); err != nil {
			return fmt.Errorf("failed to delete access token %w", err)
		}
	} else {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in target cluster for terminal identifier: %s", t.Spec.Identifier)
	}

	return nil
}

func (r *TerminalReconciler) deleteHostClusterDependencies(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	if hostClientSet != nil {
		if err := deleteAttachPodSecret(ctx, hostClientSet, t); err != nil {
			return fmt.Errorf("failed to delete attach pod secret: %w", err)
		}

		if err := hostClientSet.DeletePod(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier); err != nil {
			return fmt.Errorf("failed to delete terminal pod, %w", err)
		}

		if err := deleteKubeconfigSecret(ctx, hostClientSet, t); err != nil {
			return fmt.Errorf("failed to delete kubeconfig secret for target cluster, %w", err)
		}

		if err := deleteTokenSecret(ctx, hostClientSet, t); err != nil {
			return fmt.Errorf("failed to delete token secret for target cluster, %w", err)
		}

		if ptr.Deref(t.Spec.Host.TemporaryNamespace, false) {
			if err := hostClientSet.DeleteNamespace(ctx, *t.Spec.Host.Namespace); err != nil {
				return fmt.Errorf("failed to delete temporary namespace on host cluster, %w", err)
			}
		}
	} else {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in host cluster for terminal identifier: %s", t.Spec.Identifier)
	}

	return nil
}

func (r *TerminalReconciler) deleteAccessToken(ctx context.Context, targetClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: *t.Spec.Target.Namespace, Name: extensionsv1alpha1.TerminalAccessResourceNamePrefix + t.Spec.Identifier}}

	if t.Spec.Target.RoleName != "" && t.Spec.Target.BindingKind != "" {
		roleBinding := &extensionsv1alpha1.RoleBinding{
			NameSuffix: "", // must not be set
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole", // only ClusterRole was possible
				Name:     t.Spec.Target.RoleName,
			},
			BindingKind: t.Spec.Target.BindingKind,
		}

		if err := deleteBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, roleBinding); err != nil {
			return err
		}
	}

	if t.Spec.Target.Authorization != nil {
		for _, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
			if err := deleteBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, &roleBinding); err != nil {
				return err
			}
		}

		if ptr.Deref(r.getConfig().HonourProjectMemberships, false) {
			for _, projectMembership := range t.Spec.Target.Authorization.ProjectMemberships {
				if projectMembership.ProjectName != "" && len(projectMembership.Roles) > 0 {
					if err := r.removeServiceAccountFromProjectMember(ctx, targetClientSet, projectMembership, serviceAccount); err != nil {
						return err
					}
				}
			}
		}
	}

	if err := client.IgnoreNotFound(targetClientSet.Delete(ctx, serviceAccount)); err != nil {
		if !kErros.IsForbidden(err) {
			return err
		}
		// in case of forbidden error, try to read the service account with the terminal-controller-manager's client to be able to check if the service account was already removed
		if rErr := r.Get(ctx, client.ObjectKey{Name: serviceAccount.Name, Namespace: serviceAccount.Namespace}, serviceAccount); rErr != nil {
			if !kErros.IsNotFound(rErr) {
				return err // return original error
			} // else: already removed continue
		}
	}

	if ptr.Deref(t.Spec.Target.TemporaryNamespace, false) {
		if err := targetClientSet.DeleteNamespace(ctx, *t.Spec.Target.Namespace); err != nil {
			return err
		}
	}

	return nil
}

func (r *TerminalReconciler) removeServiceAccountFromProjectMember(ctx context.Context, targetClientSet *gardenclient.ClientSet, projectMembership extensionsv1alpha1.ProjectMembership, serviceAccount *corev1.ServiceAccount) error {
	project := &gardencorev1beta1.Project{}
	if err := targetClientSet.Get(ctx, client.ObjectKey{Name: projectMembership.ProjectName}, project); err != nil {
		if kErros.IsNotFound(err) {
			return nil // nothing to remove
		}

		if !kErros.IsForbidden(err) {
			return err
		}

		// in case of forbidden error, try to read the project with the terminal-controller-manager's client to be able to check if the service account was already removed as project member
		if rErr := r.Get(ctx, client.ObjectKey{Name: projectMembership.ProjectName}, project); rErr != nil {
			if kErros.IsNotFound(rErr) {
				return nil // nothing to remove
			}

			return err // return original error
		}
	}

	return gardenclient.RemoveServiceAccountFromProjectMember(ctx, targetClientSet, project, client.ObjectKeyFromObject(serviceAccount))
}

func deleteBinding(ctx context.Context, targetClientSet *gardenclient.ClientSet, identifier string, namespace string, roleBinding *extensionsv1alpha1.RoleBinding) error {
	bindingName := extensionsv1alpha1.TerminalAccessResourceNamePrefix + identifier + roleBinding.NameSuffix

	var err error

	switch roleBinding.BindingKind {
	case extensionsv1alpha1.BindingKindClusterRoleBinding:
		err = targetClientSet.DeleteClusterRoleBinding(ctx, bindingName)
	case extensionsv1alpha1.BindingKindRoleBinding:
		err = targetClientSet.DeleteRoleBinding(ctx, namespace, bindingName)
	default:
		return fmt.Errorf("unknown BindingKind %s", roleBinding.BindingKind) // should not happen; is validated in webhook
	}

	if err != nil {
		return err
	}

	return nil
}

func deleteAttachPodSecret(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	if err := hostClientSet.DeleteRoleBinding(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier); err != nil {
		return err
	}

	if err := hostClientSet.DeleteServiceAccount(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier); err != nil {
		return err
	}

	return hostClientSet.DeleteRole(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachRoleResourceNamePrefix+t.Spec.Identifier)
}

// isSameCluster checks if two ClusterCredentials refer to the same cluster
func isSameCluster(c1, c2 extensionsv1alpha1.ClusterCredentials) bool {
	if extensionsv1alpha1.EqualShootRefs(c1.ShootRef, c2.ShootRef) {
		return true
	}

	if extensionsv1alpha1.EqualServiceAccountRefs(c1.ServiceAccountRef, c2.ServiceAccountRef) {
		return true
	}

	return false
}

func (r *TerminalReconciler) reconcileTerminal(ctx context.Context, targetClientSet *gardenclient.ClientSet, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) error {
	if ptr.Deref(r.getConfig().HonourCleanupProjectMembership, false) {
		if ptr.Deref(t.Spec.Target.CleanupProjectMembership, false) &&
			t.Spec.Target.Credentials.ServiceAccountRef != nil && utils.IsAllowed(r.getConfig().Controllers.ServiceAccount.AllowedServiceAccountNames, t.Spec.Target.Credentials.ServiceAccountRef.Name) {
			if err := ensureServiceAccountMembershipCleanup(ctx, targetClientSet, *t.Spec.Target.Credentials.ServiceAccountRef); err != nil {
				return fmt.Errorf("failed to add referenced label to target Service Account referenced in Terminal: %w", err)
			}
		}
	}

	if err := r.createOrUpdateAttachServiceAccount(ctx, hostClientSet, t, labelSet, annotationSet); err != nil {
		return fmt.Errorf("failed to create or update resources needed for attaching to a pod: %w", err)
	}

	accessServiceAccount, err := r.createOrUpdateAccessServiceAccount(ctx, targetClientSet, t, labelSet, annotationSet)
	if err != nil {
		return err
	}

	kubeconfig, err := createOrUpdateKubeconfigSecret(ctx, targetClientSet, hostClientSet, t, labelSet, annotationSet)
	if err != nil {
		return fmt.Errorf("failed to create or update kubeconfig secret: %w", err)
	}

	useProjectedToken := isSameCluster(t.Spec.Host.Credentials, t.Spec.Target.Credentials) &&
		*t.Spec.Host.Namespace == *t.Spec.Target.Namespace

	options := terminalPodOptions{
		kubeconfigSecretName: kubeconfig.Name,
		useProjectedToken:    useProjectedToken,
		serviceAccountName:   accessServiceAccount.Name,
	}

	if !useProjectedToken {
		accessServiceAccountToken, err := targetClientSet.RequestToken(ctx, accessServiceAccount, r.getConfig().Controllers.Terminal.TokenRequestExpirationSeconds)
		if err != nil {
			return fmt.Errorf("failed to request token for access service account: %w", err)
		}

		token, err := createOrUpdateServiceAccountTokenSecret(ctx, hostClientSet, t, accessServiceAccountToken, labelSet, annotationSet)
		if err != nil {
			return fmt.Errorf("failed to create or update token secret: %w", err)
		}

		options.tokenSecretName = token.Name
		options.serviceAccountName = ""
	}

	if err = r.createOrUpdateTerminalPod(ctx, hostClientSet, t, labelSet, annotationSet, options); err != nil {
		return fmt.Errorf("failed to create or update terminal pod: %w", err)
	}

	return nil
}

// ensureServiceAccountMembershipCleanup adds the TerminalReference label and also adds the ExternalTerminalName finalizer.
// This ensures that the ServiceAccountReconciler is able to cleanup the project membership of the ServiceAccount once it is
// no longer referenced by any terminal resource
func ensureServiceAccountMembershipCleanup(ctx context.Context, clientSet *gardenclient.ClientSet, ref corev1.ObjectReference) error {
	serviceAccount := &corev1.ServiceAccount{}
	if err := clientSet.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: ref.Namespace}, serviceAccount); err != nil {
		return err
	}

	if controllerutil.ContainsFinalizer(serviceAccount, extensionsv1alpha1.ExternalTerminalName) && serviceAccount.Labels[extensionsv1alpha1.TerminalReference] == "true" {
		return nil
	}

	patch := client.MergeFrom(serviceAccount.DeepCopy())

	// add finalizer so that ServiceAccountReconciler has a chance to cleanup the project membership in case of ServiceAccount deletion
	controllerutil.AddFinalizer(serviceAccount, extensionsv1alpha1.ExternalTerminalName)

	metav1.SetMetaDataLabel(&serviceAccount.ObjectMeta, extensionsv1alpha1.TerminalReference, "true")

	if err := clientSet.Patch(ctx, serviceAccount, patch); err != nil {
		return fmt.Errorf("failed to add referred label to ServiceAccount referenced in Terminal: %w", err)
	}

	return nil
}

func (r *TerminalReconciler) createOrUpdateAttachServiceAccount(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) error {
	if ptr.Deref(t.Spec.Host.TemporaryNamespace, false) {
		if _, err := hostClientSet.CreateOrUpdateNamespace(ctx, *t.Spec.Host.Namespace, labelSet, annotationSet); err != nil {
			return err
		}
	}

	attachPodServiceAccount, err := hostClientSet.CreateOrUpdateServiceAccount(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, labelSet, annotationSet)
	if err != nil {
		return err
	}

	if err = r.patchTerminalStatus(ctx, t, func(terminal *extensionsv1alpha1.Terminal) error {
		terminal.Status.AttachServiceAccountName = &attachPodServiceAccount.Name
		return nil
	}); err != nil {
		return err
	}

	podResourceName := extensionsv1alpha1.TerminalPodResourceNamePrefix + t.Spec.Identifier
	rules := []rbacv1.PolicyRule{
		{
			Resources:     []string{"pods/attach"},
			APIGroups:     []string{corev1.GroupName},
			Verbs:         []string{"get"},
			ResourceNames: []string{podResourceName},
		},
		{
			Resources:     []string{"pods"},
			APIGroups:     []string{corev1.GroupName},
			Verbs:         []string{"watch"},
			ResourceNames: []string{podResourceName},
		},
	}

	attachRole, err := hostClientSet.CreateOrUpdateRole(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachRoleResourceNamePrefix+t.Spec.Identifier, rules, labelSet, annotationSet)
	if err != nil {
		return err
	}

	subject := rbacv1.Subject{
		Kind:      rbacv1.ServiceAccountKind,
		Namespace: attachPodServiceAccount.Namespace,
		Name:      attachPodServiceAccount.Name,
	}
	roleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "Role",
		Name:     attachRole.Name,
	}

	if _, err = hostClientSet.CreateOrUpdateRoleBinding(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, subject, roleRef, labelSet, annotationSet); err != nil {
		return err
	}

	return nil
}

// terminalStatusHandler is a function type that defines a handler for updating the status of a Terminal resource.
// The function is responsible for modifying the status field of the Terminal resource based on the desired update logic.
// It should not modify any other fields of the Terminal resource.
type terminalStatusHandler func(*extensionsv1alpha1.Terminal) error

func (r *TerminalReconciler) patchTerminalStatus(ctx context.Context, t *extensionsv1alpha1.Terminal, handler terminalStatusHandler) error {
	terminal := &extensionsv1alpha1.Terminal{}

	if err := r.Get(ctx, client.ObjectKey{Name: t.Name, Namespace: t.Namespace}, terminal); err != nil {
		return err
	}

	patch := client.MergeFrom(terminal.DeepCopy())

	if err := handler(terminal); err != nil {
		return err
	}

	return r.Status().Patch(ctx, terminal, patch)
}

func (r *TerminalReconciler) createOrUpdateAccessServiceAccount(ctx context.Context, targetClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.ServiceAccount, error) {
	if ptr.Deref(t.Spec.Target.TemporaryNamespace, false) {
		if _, err := targetClientSet.CreateOrUpdateNamespace(ctx, *t.Spec.Target.Namespace, labelSet, annotationSet); err != nil {
			return nil, err
		}
	}

	accessServiceAccountAnnotations := utils.MergeStringMap(*annotationSet, map[string]string{
		extensionsv1alpha1.Description: "Temporary service account for web-terminal session. Managed by gardener/terminal-controller-manager",
	})

	accessServiceAccount, err := targetClientSet.CreateOrUpdateServiceAccount(ctx, *t.Spec.Target.Namespace, extensionsv1alpha1.TerminalAccessResourceNamePrefix+t.Spec.Identifier, labelSet, &accessServiceAccountAnnotations)
	if err != nil {
		return nil, err
	}

	// TODO can be removed once t.Spec.Target.RoleName and t.Spec.Target.BindingKind is removed from the API
	if t.Spec.Target.RoleName != "" && t.Spec.Target.BindingKind != "" {
		roleBinding := &extensionsv1alpha1.RoleBinding{
			NameSuffix: "", // must not be set to be compatible to previous versions
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole", // only ClusterRole was possible
				Name:     t.Spec.Target.RoleName,
			},
			BindingKind: t.Spec.Target.BindingKind,
		}

		if err = createOrUpdateBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, roleBinding, labelSet, annotationSet, accessServiceAccount); err != nil {
			return nil, err
		}
	}

	if t.Spec.Target.Authorization == nil {
		return accessServiceAccount, nil
	}

	for _, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
		if err = createOrUpdateBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, &roleBinding, labelSet, annotationSet, accessServiceAccount); err != nil {
			return nil, err
		}
	}

	if ptr.Deref(r.getConfig().HonourProjectMemberships, false) {
		for _, projectMembership := range t.Spec.Target.Authorization.ProjectMemberships {
			if projectMembership.ProjectName != "" && len(projectMembership.Roles) > 0 {
				project := &gardencorev1beta1.Project{}
				if err = targetClientSet.Get(ctx, client.ObjectKey{Name: projectMembership.ProjectName}, project); err != nil {
					return nil, err
				}

				if err = gardenclient.AddServiceAccountAsProjectMember(ctx, targetClientSet, project, accessServiceAccount, projectMembership.Roles); err != nil {
					return nil, err
				}
			}
		}
	}

	return accessServiceAccount, nil
}

func createOrUpdateBinding(ctx context.Context, targetClientSet *gardenclient.ClientSet, identifier string, namespace string, roleBinding *extensionsv1alpha1.RoleBinding, labelSet *labels.Set, annotationSet *utils.Set, accessServiceAccount *corev1.ServiceAccount) error {
	subject := rbacv1.Subject{
		Kind:      rbacv1.ServiceAccountKind,
		Namespace: accessServiceAccount.Namespace,
		Name:      accessServiceAccount.Name,
	}
	bindingName := extensionsv1alpha1.TerminalAccessResourceNamePrefix + identifier + roleBinding.NameSuffix

	var err error

	switch roleBinding.BindingKind {
	case extensionsv1alpha1.BindingKindClusterRoleBinding:
		_, err = targetClientSet.CreateOrUpdateClusterRoleBinding(ctx, bindingName, subject, roleBinding.RoleRef, labelSet, annotationSet)
	case extensionsv1alpha1.BindingKindRoleBinding:
		_, err = targetClientSet.CreateOrUpdateRoleBinding(ctx, namespace, bindingName, subject, roleBinding.RoleRef, labelSet, annotationSet)
	default:
		return fmt.Errorf("unknown BindingKind %s", roleBinding.BindingKind) // should not happen; is validated in webhook
	}

	if err != nil {
		return err
	}

	return nil
}

func clusterNameForCredential(cred extensionsv1alpha1.ClusterCredentials) (string, error) {
	if cred.ShootRef != nil {
		return cred.ShootRef.Name, nil
	} else if cred.ServiceAccountRef != nil {
		return cred.ServiceAccountRef.Name, nil
	}

	return "", errors.New("no cluster credentials provided")
}

func createOrUpdateKubeconfigSecret(ctx context.Context, targetClientSet *gardenclient.ClientSet, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Secret, error) {
	clusterName, err := clusterNameForCredential(t.Spec.Target.Credentials)
	if err != nil {
		return nil, err
	}

	contextNamespace := t.Spec.Target.KubeconfigContextNamespace

	var server string

	var apiServerServiceRef *corev1.ObjectReference

	if t.Spec.Target.APIServerServiceRef != nil {
		apiServerServiceRef = t.Spec.Target.APIServerServiceRef
	}

	if t.Spec.Target.APIServer != nil && t.Spec.Target.APIServer.ServiceRef != nil {
		apiServerServiceRef = t.Spec.Target.APIServer.ServiceRef
	}

	if apiServerServiceRef != nil && apiServerServiceRef.Name != "" {
		var namespace string
		if apiServerServiceRef.Namespace != "" {
			namespace = apiServerServiceRef.Namespace
		} else {
			namespace = *t.Spec.Host.Namespace
		}

		name := apiServerServiceRef.Name

		// validate that kube-apiserver service really exists
		if err = hostClientSet.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &corev1.Service{}); err != nil {
			if kErros.IsNotFound(err) {
				return nil, fmt.Errorf("kube-apiserver service %s/%s not found", namespace, name)
			}

			return nil, err
		}

		host := name + "." + namespace + ".svc"

		baseURL, err := url.Parse("https://" + host)
		if err != nil {
			return nil, err
		}

		server = baseURL.String()
	} else if t.Spec.Target.APIServer != nil && len(t.Spec.Target.APIServer.Server) > 0 {
		server = t.Spec.Target.APIServer.Server
	} else {
		server = targetClientSet.Host
	}

	var caData []byte
	if t.Spec.Target.APIServer != nil {
		caData = t.Spec.Target.APIServer.CAData
	}

	kubeconfig, err := GenerateKubeconfig(clusterName, contextNamespace, server, caData)
	if err != nil {
		return nil, err
	}

	kubeconfigSecretName := extensionsv1alpha1.KubeconfigSecretResourceNamePrefix + t.Spec.Identifier

	data := map[string][]byte{
		gardenclient.DataKeyKubeConfig: kubeconfig,
	}

	return hostClientSet.CreateOrUpdateSecretData(ctx, *t.Spec.Host.Namespace, kubeconfigSecretName, data, labelSet, annotationSet)
}

func createOrUpdateServiceAccountTokenSecret(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, token string, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Secret, error) {
	secretName := extensionsv1alpha1.TokenSecretResourceNamePrefix + t.Spec.Identifier

	data := map[string][]byte{
		gardenclient.DataKeyToken: []byte(token),
	}

	return hostClientSet.CreateOrUpdateSecretData(ctx, *t.Spec.Host.Namespace, secretName, data, labelSet, annotationSet)
}

func deleteKubeconfigSecret(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	kubeconfigSecretName := extensionsv1alpha1.KubeconfigSecretResourceNamePrefix + t.Spec.Identifier
	return hostClientSet.DeleteSecret(ctx, *t.Spec.Host.Namespace, kubeconfigSecretName)
}

func deleteTokenSecret(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	kubeconfigSecretName := extensionsv1alpha1.TokenSecretResourceNamePrefix + t.Spec.Identifier
	return hostClientSet.DeleteSecret(ctx, *t.Spec.Host.Namespace, kubeconfigSecretName)
}

// GenerateKubeconfig generates a kubeconfig to authenticate against the provided server.
// If the server points to localhost, the kubernetes default service is used instead as server.
func GenerateKubeconfig(clusterName string, contextNamespace string, server string, caData []byte) ([]byte, error) {
	if server == "" {
		return nil, errors.New("api server host is required")
	}

	matched, _ := regexp.MatchString(`^https:\/\/localhost:\d{1,5}$`, server)
	if matched {
		server = "https://kubernetes.default.svc.cluster.local"
	}

	kubeconfig := &clientcmdv1.Config{
		APIVersion: "v1",
		Kind:       "Config",
		Preferences: clientcmdv1.Preferences{
			Colors: false,
		},
		Clusters: []clientcmdv1.NamedCluster{
			{
				Name: clusterName,
				Cluster: clientcmdv1.Cluster{
					Server:                   server,
					InsecureSkipTLSVerify:    false,
					CertificateAuthorityData: caData,
				},
			},
		},
		AuthInfos: []clientcmdv1.NamedAuthInfo{
			{
				Name: clusterName,
				AuthInfo: clientcmdv1.AuthInfo{
					TokenFile: "/mnt/.auth/token",
				},
			},
		},
		Contexts: []clientcmdv1.NamedContext{
			{
				Name: clusterName,
				Context: clientcmdv1.Context{
					Cluster:   clusterName,
					AuthInfo:  clusterName,
					Namespace: contextNamespace,
				},
			},
		},
		CurrentContext: clusterName,
	}

	return yaml.Marshal(kubeconfig)
}

// terminalPodOptions contains configuration options for creating or updating a terminal Pod.
type terminalPodOptions struct {
	// kubeconfigSecretName is the name of the secret containing the kubeconfig to be mounted in the Pod.
	kubeconfigSecretName string

	// useProjectedToken indicates whether to use a projected service account token volume.
	useProjectedToken bool

	// tokenSecretName is the name of the secret to use for the token volume when not using a projected token.
	tokenSecretName string

	// serviceAccountName is the name of the service account to use when a projected token volume is configured.
	serviceAccountName string
}

func (r *TerminalReconciler) createOrUpdateTerminalPod(ctx context.Context, cs *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set, options terminalPodOptions) error {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: *t.Spec.Host.Namespace, Name: extensionsv1alpha1.TerminalPodResourceNamePrefix + t.Spec.Identifier}}

	const (
		containerName                 = "terminal"
		initContainerName             = "setup"
		kubeconfigReadWriteVolumeName = "kubeconfig-rw"
		kubeconfigReadOnlyVolumeName  = "kubeconfig"
		tokenVolumeName               = "token"
	)

	if err := gardenclient.CreateOrUpdateDiscardResult(ctx, cs, pod, func() error {
		pod.Labels = labels.Merge(pod.Labels, t.Spec.Host.Pod.Labels)
		pod.Labels = labels.Merge(pod.Labels, *labelSet)
		pod.Annotations = utils.MergeStringMap(pod.Annotations, *annotationSet)

		image := t.Spec.Host.Pod.ContainerImage
		privileged := t.Spec.Host.Pod.Privileged

		if t.Spec.Host.Pod.Container != nil {
			image = t.Spec.Host.Pod.Container.Image
			privileged = t.Spec.Host.Pod.Container.Privileged
		}

		pod.Spec.AutomountServiceAccountToken = ptr.To(false)

		pod.Spec.HostPID = t.Spec.Host.Pod.HostPID
		pod.Spec.HostNetwork = t.Spec.Host.Pod.HostNetwork

		if t.Spec.Host.Pod.HostNetwork {
			// For Pods running with hostNetwork, we need to explicitly set its DNS policy "ClusterFirstWithHostNet"
			pod.Spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
		}

		mountHostRootFs := privileged || t.Spec.Host.Pod.HostPID || t.Spec.Host.Pod.HostNetwork

		if len(pod.Spec.Containers) == 0 {
			// initialize values that cannot be updated
			if options.useProjectedToken {
				pod.Spec.ServiceAccountName = options.serviceAccountName
			}

			container := corev1.Container{Name: containerName}

			container.VolumeMounts = []corev1.VolumeMount{
				{
					Name:      kubeconfigReadWriteVolumeName,
					MountPath: "/mnt/.kube",
				},
				{
					Name:      tokenVolumeName,
					MountPath: "/mnt/.auth",
					ReadOnly:  true,
				},
			}
			container.Env = []corev1.EnvVar{
				{
					Name:  "KUBECONFIG",
					Value: "/mnt/.kube/config",
				},
			}

			if t.Spec.Host.Pod.Container != nil {
				container.Command = t.Spec.Host.Pod.Container.Command
				container.Args = t.Spec.Host.Pod.Container.Args
				container.Resources = t.Spec.Host.Pod.Container.Resources
			}

			if mountHostRootFs {
				rootVolumeName := "root-volume"
				container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
					Name:      rootVolumeName,
					MountPath: "/host",
				})
				pod.Spec.Volumes = []corev1.Volume{
					{
						Name: rootVolumeName,
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/",
							},
						},
					},
				}
			}

			pod.Spec.Containers = []corev1.Container{container}

			pod.Spec.InitContainers = []corev1.Container{{
				Name:  initContainerName,
				Image: image,
				Command: []string{
					"/bin/cp",
					"/mnt/.kube-ro/config",
					"/mnt/.kube-rw/config",
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						MountPath: "/mnt/.kube-rw",
						Name:      kubeconfigReadWriteVolumeName,
					},
					{
						MountPath: "/mnt/.kube-ro",
						Name:      kubeconfigReadOnlyVolumeName,
					},
				},
			}}

			tokenVolume := corev1.Volume{
				Name:         tokenVolumeName,
				VolumeSource: corev1.VolumeSource{},
			}
			if options.useProjectedToken {
				tokenVolume.Projected = &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								Path:              "token",
								ExpirationSeconds: ptr.To(int64(time.Hour.Seconds())),
							},
						},
					},
				}
				pod.Spec.ServiceAccountName = options.serviceAccountName
			} else {
				tokenVolume.Secret = &corev1.SecretVolumeSource{
					SecretName: options.tokenSecretName,
				}
			}

			pod.Spec.Volumes = append(pod.Spec.Volumes, []corev1.Volume{
				{
					Name: kubeconfigReadOnlyVolumeName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: options.kubeconfigSecretName,
							Items: []corev1.KeyToPath{
								{
									Key:  gardenclient.DataKeyKubeConfig,
									Path: "config",
								},
							},
						},
					},
				},
				{
					Name: kubeconfigReadWriteVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumDefault},
					},
				},
				tokenVolume,
			}...)
		}
		// update values that can be updated
		var (
			containerFound bool
			containerIndex int
		)

		for k, v := range pod.Spec.Containers {
			if v.Name == containerName {
				containerIndex = k
				containerFound = true

				break
			}
		}

		if !containerFound {
			return errors.New("terminal container not found")
		}

		pod.Spec.Containers[containerIndex].Image = image
		pod.Spec.Containers[containerIndex].Stdin = true
		pod.Spec.Containers[containerIndex].TTY = true

		if pod.Spec.Containers[containerIndex].SecurityContext == nil {
			pod.Spec.Containers[containerIndex].SecurityContext = &corev1.SecurityContext{}
		}

		pod.Spec.Containers[containerIndex].SecurityContext.Privileged = &privileged

		pod.Spec.NodeSelector = t.Spec.Host.Pod.NodeSelector

		if len(t.Spec.Host.Pod.NodeSelector) > 0 {
			if len(pod.Spec.Tolerations) == 0 {
				pod.Spec.Tolerations = []corev1.Toleration{}
			}

			existsToleration := corev1.Toleration{
				Operator: corev1.TolerationOpExists,
			}
			if !tolerationExists(pod.Spec.Tolerations, match(existsToleration)) {
				pod.Spec.Tolerations = append(pod.Spec.Tolerations, existsToleration)
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return r.patchTerminalStatus(ctx, t, func(terminal *extensionsv1alpha1.Terminal) error {
		terminal.Status.PodName = &pod.Name
		return nil
	})
}

// reconcileProcessing returns a LastOperation with state processing.
func reconcileProcessing(t extensionsv1alpha1.LastOperationType, description string) *extensionsv1alpha1.LastOperation {
	return lastOperation(t, extensionsv1alpha1.LastOperationStateProcessing, description)
}

// reconcileSucceeded returns a LastOperation with state succeeded.
func reconcileSucceeded(t extensionsv1alpha1.LastOperationType, description string) *extensionsv1alpha1.LastOperation {
	return lastOperation(t, extensionsv1alpha1.LastOperationStateSucceeded, description)
}

// reconcileError returns a LastOperation with state error with the given description and codes.
func reconcileError(t extensionsv1alpha1.LastOperationType, description string) *extensionsv1alpha1.LastOperation {
	return lastOperation(t, extensionsv1alpha1.LastOperationStateError, description)
}

// lastOperation creates a new LastOperation from the given parameters.
func lastOperation(t extensionsv1alpha1.LastOperationType, state extensionsv1alpha1.LastOperationState, description string) *extensionsv1alpha1.LastOperation {
	return &extensionsv1alpha1.LastOperation{
		LastUpdateTime: metav1.Now(),
		Type:           t,
		State:          state,
		Description:    description,
	}
}

// lastError creates a new LastError from the given parameters.
func lastError(description string) *extensionsv1alpha1.LastError {
	return &extensionsv1alpha1.LastError{
		LastUpdateTime: metav1.Now(),
		Description:    description,
	}
}

type tolerationMatchFunc func(toleration corev1.Toleration) bool

func tolerationExists(tolerations []corev1.Toleration, matchFunc tolerationMatchFunc) bool {
	for _, toleration := range tolerations {
		if matchFunc(toleration) {
			return true
		}
	}

	return false
}

func matchByKey(key string) tolerationMatchFunc {
	return func(toleration corev1.Toleration) bool {
		return toleration.Key == key
	}
}

func match(matchToleration corev1.Toleration) tolerationMatchFunc {
	return func(toleration corev1.Toleration) bool {
		return apiequality.Semantic.DeepEqual(toleration, matchToleration)
	}
}
