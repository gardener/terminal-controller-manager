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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
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
		For(&extensionsv1alpha1.Terminal{}).
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
	// Fetch the Terminal t
	t := &extensionsv1alpha1.Terminal{}

	err := r.Get(ctx, req.NamespacedName, t)
	if err != nil {
		if kErros.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the req.
		return ctrl.Result{}, err
	}

	gardenClientSet := r.ClientSet

	cfg := r.getConfig()

	hostClientSet, hostClientSetErr := gardenclient.NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Host.Credentials, cfg.HonourServiceAccountRefHostCluster, cfg.Controllers.Terminal.TokenRequestExpirationSeconds, r.Scheme)
	targetClientSet, targetClientSetErr := gardenclient.NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Target.Credentials, cfg.HonourServiceAccountRefTargetCluster, cfg.Controllers.Terminal.TokenRequestExpirationSeconds, r.Scheme)

	if !t.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is being deleted
		if controllerutil.ContainsFinalizer(t, extensionsv1alpha1.TerminalName) {
			// in case of deletion we should be able to continue even if one of the secrets (host, target(, ingress)) is not there anymore, e.g. if the corresponding cluster was deleted
			if hostClientSetErr != nil && !kErros.IsNotFound(hostClientSetErr) {
				return ctrl.Result{}, hostClientSetErr
			}

			if targetClientSetErr != nil && !kErros.IsNotFound(targetClientSetErr) {
				return ctrl.Result{}, targetClientSetErr
			}

			r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleting, "Deleting external dependencies")
			// our finalizer is present, so lets handle our external dependency

			if deletionErrors := r.deleteExternalDependency(ctx, targetClientSet, hostClientSet, t); deletionErrors != nil {
				var errStrings []string
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				for _, deletionErr := range deletionErrors {
					r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventDeleteError, deletionErr.Description)
					errStrings = append(errStrings, deletionErr.Description)
				}

				return ctrl.Result{}, errors.New(strings.Join(errStrings, "\n"))
			}

			r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleted, "Deleted external dependencies")

			// remove our finalizer from the list and update it.
			controllerutil.RemoveFinalizer(t, extensionsv1alpha1.TerminalName)

			return ctrl.Result{}, r.Update(ctx, t)
		}

		// Our finalizer has finished, so the reconciler can do nothing.
		return ctrl.Result{}, nil
	}

	if hostClientSetErr != nil {
		return ctrl.Result{}, hostClientSetErr
	}

	if targetClientSetErr != nil {
		return ctrl.Result{}, targetClientSetErr
	}

	if err = r.ensureAdmissionWebhookConfigured(ctx, gardenClientSet, t); err != nil {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, err.Error())
		return ctrl.Result{}, err
	}

	// The object is not being deleted, so if it does not have our finalizer,
	// then lets add the finalizer and update the object.
	finalizers := sets.NewString(t.Finalizers...)
	if !finalizers.Has(extensionsv1alpha1.TerminalName) {
		finalizers.Insert(extensionsv1alpha1.TerminalName)
		t.Finalizers = finalizers.UnsortedList()

		return ctrl.Result{}, r.Update(ctx, t)
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

	if err := r.reconcileTerminal(ctx, targetClientSet, hostClientSet, t, labelSet, annotationSet); err != nil {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, err.Description)
		return ctrl.Result{}, errors.New(err.Description)
	}

	r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventReconciled, "Reconciled Terminal state")

	return ctrl.Result{}, nil
}

func (r *TerminalReconciler) recordEventAndLog(ctx context.Context, t *extensionsv1alpha1.Terminal, eventType, reason, messageFmt string, args ...interface{}) {
	r.Recorder.Eventf(t, eventType, reason, messageFmt, args...)
	log.FromContext(ctx).Info(fmt.Sprintf(messageFmt, args...))
}

func (r *TerminalReconciler) ensureAdmissionWebhookConfigured(ctx context.Context, gardenClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) error {
	webhookConfigurationOptions := metav1.ListOptions{}
	webhookConfigurationOptions.LabelSelector = labels.SelectorFromSet(map[string]string{
		"app.kubernetes.io/name":      "terminal",
		"app.kubernetes.io/component": "admission-controller",
	}).String()

	mutatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
	if err != nil {
		return errors.New(err.Error())
	}

	if len(mutatingWebhookConfigurations.Items) != 1 {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("expected 1 MutatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(mutatingWebhookConfigurations.Items))
	}

	mutatingWebhookConfiguration := mutatingWebhookConfigurations.Items[0]
	if mutatingWebhookConfiguration.ObjectMeta.CreationTimestamp.After(t.ObjectMeta.CreationTimestamp.Time) {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("terminal %s has been created before mutating webhook was configured. Deleting resource", t.ObjectMeta.Name)
	}

	validatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
	if err != nil {
		return errors.New(err.Error())
	}

	if len(validatingWebhookConfigurations.Items) != 1 {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("expected 1 ValidatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(validatingWebhookConfigurations.Items))
	}

	validatingWebhookConfiguration := validatingWebhookConfigurations.Items[0]
	if validatingWebhookConfiguration.ObjectMeta.CreationTimestamp.After(t.ObjectMeta.CreationTimestamp.Time) {
		if err = client.IgnoreNotFound(gardenClientSet.Delete(ctx, t)); err != nil {
			return err
		}

		return fmt.Errorf("terminal %s has been created before validating webhook was configured. Deleting resource", t.ObjectMeta.Name)
	}

	return nil
}

// deleteExternalDependency deletes external dependencies on target and host cluster. In case of an error on the target cluster (e.g. api server cannot be reached) the dependencies on the host cluster are still tried to delete.
func (r *TerminalReconciler) deleteExternalDependency(ctx context.Context, targetClientSet *gardenclient.ClientSet, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) []*extensionsv1alpha1.LastError {
	var lastErrors []*extensionsv1alpha1.LastError

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

func (r *TerminalReconciler) deleteTargetClusterDependencies(ctx context.Context, targetClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) *extensionsv1alpha1.LastError {
	if targetClientSet != nil {
		if err := r.deleteAccessToken(ctx, targetClientSet, t); err != nil {
			return formatError("Failed to delete access token", err)
		}
	} else {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in target cluster for terminal identifier: %s", t.Spec.Identifier)
	}

	return nil
}

func (r *TerminalReconciler) deleteHostClusterDependencies(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal) *extensionsv1alpha1.LastError {
	if hostClientSet != nil {
		if err := deleteAttachPodSecret(ctx, hostClientSet, t); err != nil {
			return formatError("Failed to delete attach pod secret", err)
		}

		if err := hostClientSet.DeletePod(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier); err != nil {
			return formatError("Failed to delete terminal pod", err)
		}

		if err := deleteKubeconfigSecret(ctx, hostClientSet, t); err != nil {
			return formatError("failed to delete kubeconfig secret for target cluster", err)
		}

		if err := deleteTokenSecret(ctx, hostClientSet, t); err != nil {
			return formatError("failed to delete token secret for target cluster", err)
		}

		if ptr.Deref(t.Spec.Host.TemporaryNamespace, false) {
			if err := hostClientSet.DeleteNamespace(ctx, *t.Spec.Host.Namespace); err != nil {
				return formatError("failed to delete temporary namespace on host cluster", err)
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

func (r *TerminalReconciler) reconcileTerminal(ctx context.Context, targetClientSet *gardenclient.ClientSet, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) *extensionsv1alpha1.LastError {
	if ptr.Deref(r.getConfig().HonourCleanupProjectMembership, false) {
		if ptr.Deref(t.Spec.Target.CleanupProjectMembership, false) &&
			t.Spec.Target.Credentials.ServiceAccountRef != nil && utils.IsAllowed(r.getConfig().Controllers.ServiceAccount.AllowedServiceAccountNames, t.Spec.Target.Credentials.ServiceAccountRef.Name) {
			if err := ensureServiceAccountMembershipCleanup(ctx, targetClientSet, *t.Spec.Target.Credentials.ServiceAccountRef); err != nil {
				return formatError("failed to add referenced label to target Service Account referenced in Terminal: %w", err)
			}
		}
	}

	if err := r.createOrUpdateAttachPodSecret(ctx, hostClientSet, t, labelSet, annotationSet); err != nil {
		return formatError("Failed to create or update resources needed for attaching to a pod", err)
	}

	secretNames, err := r.createOrUpdateAdminKubeconfigAndTokenSecrets(ctx, targetClientSet, hostClientSet, t, labelSet, annotationSet)
	if err != nil {
		return formatError("Failed to create or update admin kubeconfig", err)
	}

	if _, err = r.createOrUpdateTerminalPod(ctx, hostClientSet, t, secretNames, labelSet, annotationSet); err != nil {
		return formatError("Failed to create or update terminal pod", err)
	}

	return nil
}

// ensureServiceAccountMembershipCleanup adds the TerminalReference label and also adds the ExternalTerminalName finalizer.
// This ensures that the ServiceAccountReconciler is able to cleanup the poject membership of the ServiceAccount once it is
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

func (r *TerminalReconciler) createOrUpdateAttachPodSecret(ctx context.Context, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) error {
	if ptr.Deref(t.Spec.Host.TemporaryNamespace, false) {
		if _, err := hostClientSet.CreateOrUpdateNamespace(ctx, *t.Spec.Host.Namespace, labelSet, annotationSet); err != nil {
			return err
		}
	}

	attachPodServiceAccount, err := hostClientSet.CreateOrUpdateServiceAccount(ctx, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, labelSet, annotationSet)
	if err != nil {
		return err
	}

	if err = r.updateTerminalStatusAttachServiceAccountName(ctx, t, attachPodServiceAccount.Name); err != nil {
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

func (r *TerminalReconciler) updateTerminalStatusAttachServiceAccountName(ctx context.Context, t *extensionsv1alpha1.Terminal, attachServiceAccountName string) error {
	terminal := &extensionsv1alpha1.Terminal{}

	// make sure to fetch the latest version of the terminal resource before updating its status
	if err := r.Get(ctx, client.ObjectKey{Name: t.Name, Namespace: t.Namespace}, terminal); err != nil {
		return err
	}

	terminal.Status.AttachServiceAccountName = attachServiceAccountName

	return r.Status().Update(ctx, terminal)
}

func (r *TerminalReconciler) updateTerminalStatusPodName(ctx context.Context, t *extensionsv1alpha1.Terminal, podName string) error {
	terminal := &extensionsv1alpha1.Terminal{}

	// make sure to fetch the latest version of the terminal resource before updating its status
	if err := r.Get(ctx, client.ObjectKey{Name: t.Name, Namespace: t.Namespace}, terminal); err != nil {
		return err
	}

	terminal.Status.PodName = podName

	return r.Status().Update(ctx, terminal)
}

type volumeSourceSecretNames struct {
	kubeconfig string
	token      string
}

func (r *TerminalReconciler) createOrUpdateAdminKubeconfigAndTokenSecrets(ctx context.Context, targetClientSet *gardenclient.ClientSet, hostClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) (*volumeSourceSecretNames, error) {
	accessServiceAccountToken, err := r.createOrUpdateAccessServiceAccountAndRequestToken(ctx, targetClientSet, t, labelSet, annotationSet)
	if err != nil {
		return nil, err
	}

	kubeconfig, err := createOrUpdateKubeconfigSecret(ctx, targetClientSet, hostClientSet, t, labelSet, annotationSet)
	if err != nil {
		return nil, fmt.Errorf("failed to create or update kubeconfig secret: %w", err)
	}

	token, err := createOrUpdateServiceAccountTokenSecret(ctx, hostClientSet, t, accessServiceAccountToken, labelSet, annotationSet)
	if err != nil {
		return nil, fmt.Errorf("failed to create or update token secret: %w", err)
	}

	return &volumeSourceSecretNames{
		kubeconfig: kubeconfig.Name,
		token:      token.Name,
	}, nil
}

func (r *TerminalReconciler) createOrUpdateAccessServiceAccountAndRequestToken(ctx context.Context, targetClientSet *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) (string, error) {
	if ptr.Deref(t.Spec.Target.TemporaryNamespace, false) {
		if _, err := targetClientSet.CreateOrUpdateNamespace(ctx, *t.Spec.Target.Namespace, labelSet, annotationSet); err != nil {
			return "", err
		}
	}

	accessServiceAccountAnnotations := utils.MergeStringMap(*annotationSet, map[string]string{
		extensionsv1alpha1.Description: "Temporary service account for web-terminal session. Managed by gardener/terminal-controller-manager",
	})

	accessServiceAccount, err := targetClientSet.CreateOrUpdateServiceAccount(ctx, *t.Spec.Target.Namespace, extensionsv1alpha1.TerminalAccessResourceNamePrefix+t.Spec.Identifier, labelSet, &accessServiceAccountAnnotations)
	if err != nil {
		return "", err
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
			return "", err
		}
	}

	if t.Spec.Target.Authorization != nil {
		for _, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
			if err = createOrUpdateBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, &roleBinding, labelSet, annotationSet, accessServiceAccount); err != nil {
				return "", err
			}
		}

		if ptr.Deref(r.getConfig().HonourProjectMemberships, false) {
			for _, projectMembership := range t.Spec.Target.Authorization.ProjectMemberships {
				if projectMembership.ProjectName != "" && len(projectMembership.Roles) > 0 {
					project := &gardencorev1beta1.Project{}
					if err = targetClientSet.Get(ctx, client.ObjectKey{Name: projectMembership.ProjectName}, project); err != nil {
						return "", err
					}

					if err = gardenclient.AddServiceAccountAsProjectMember(ctx, targetClientSet, project, accessServiceAccount, projectMembership.Roles); err != nil {
						return "", err
					}
				}
			}
		}
	}

	childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return targetClientSet.RequestToken(childCtx, accessServiceAccount, r.getConfig().Controllers.Terminal.TokenRequestExpirationSeconds)
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
	} else if cred.SecretRef != nil {
		return cred.SecretRef.Name, nil
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

func (r *TerminalReconciler) createOrUpdateTerminalPod(ctx context.Context, cs *gardenclient.ClientSet, t *extensionsv1alpha1.Terminal, secretNames *volumeSourceSecretNames, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Pod, error) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: *t.Spec.Host.Namespace, Name: extensionsv1alpha1.TerminalPodResourceNamePrefix + t.Spec.Identifier}}

	const (
		containerName                 = "terminal"
		initContainerName             = "setup"
		kubeconfigReadWriteVolumeName = "kubeconfig-rw"
		kubeconfigReadOnlyVolumeName  = "kubeconfig"
		tokenVolumeName               = "token"
	)

	if err := r.updateTerminalStatusPodName(ctx, t, pod.Name); err != nil {
		return nil, err
	}

	return pod, gardenclient.CreateOrUpdateDiscardResult(ctx, cs, pod, func() error {
		pod.Labels = labels.Merge(pod.Labels, t.Spec.Host.Pod.Labels)
		pod.Labels = labels.Merge(pod.Labels, *labelSet)
		pod.Annotations = utils.MergeStringMap(pod.Annotations, *annotationSet)

		image := t.Spec.Host.Pod.ContainerImage
		privileged := t.Spec.Host.Pod.Privileged

		if t.Spec.Host.Pod.Container != nil {
			image = t.Spec.Host.Pod.Container.Image
			privileged = t.Spec.Host.Pod.Container.Privileged
		}

		automountServiceAccountToken := false
		pod.Spec.AutomountServiceAccountToken = &automountServiceAccountToken

		pod.Spec.HostPID = t.Spec.Host.Pod.HostPID
		pod.Spec.HostNetwork = t.Spec.Host.Pod.HostNetwork

		if t.Spec.Host.Pod.HostNetwork {
			// For Pods running with hostNetwork, we need to explicitly set its DNS policy "ClusterFirstWithHostNet"
			pod.Spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
		}

		mountHostRootFs := privileged || t.Spec.Host.Pod.HostPID || t.Spec.Host.Pod.HostNetwork

		if len(pod.Spec.Containers) == 0 {
			// initialize values that cannot be updated
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
			pod.Spec.Volumes = append(pod.Spec.Volumes, []corev1.Volume{
				{
					Name: kubeconfigReadOnlyVolumeName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: secretNames.kubeconfig,
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
				{
					Name: tokenVolumeName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: secretNames.token,
						},
					},
				},
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
	})
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

// code below copied from gardener/gardener

// TODO move to utils
func formatError(message string, err error) *extensionsv1alpha1.LastError {
	return &extensionsv1alpha1.LastError{
		Description: fmt.Sprintf("%s (%s)", message, err.Error()),
	}
}
