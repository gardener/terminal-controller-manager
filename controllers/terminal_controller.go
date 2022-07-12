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

	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencoreclientset "github.com/gardener/gardener/pkg/client/core/clientset/versioned"
	gardenscheme "github.com/gardener/gardener/pkg/client/core/clientset/versioned/scheme"
	"golang.org/x/oauth2/google"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	kErros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/client-go/tools/record"
	watchtools "k8s.io/client-go/tools/watch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"

	extensionsv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/utils"
)

// TerminalReconciler reconciles a Terminal object
type TerminalReconciler struct {
	Scheme *runtime.Scheme
	*ClientSet
	Recorder                    record.EventRecorder
	Config                      *extensionsv1alpha1.ControllerManagerConfiguration
	ReconcilerCountPerNamespace map[string]int
	mutex                       sync.RWMutex
	configMutex                 sync.RWMutex
}

type ClientSet struct {
	*rest.Config
	client.Client
	Kubernetes kubernetes.Interface
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
		return fmt.Errorf("max count reached")
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
		panic("entry expected!")
	}

	counter = c - 1
	if counter == 0 {
		delete(r.ReconcilerCountPerNamespace, namespace)
	} else {
		r.ReconcilerCountPerNamespace[namespace] = counter
	}
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create;
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups=dashboard.gardener.cloud,resources=terminals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dashboard.gardener.cloud,resources=terminals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.gardener.cloud,resources=projects,verbs=get;list;watch
// +kubebuilder:rbac:groups=core.gardener.cloud,resources=shoots/adminkubeconfig,verbs=create
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations;mutatingwebhookconfigurations,verbs=list

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
	// TODO introduce unique reconcile identifier that is used for logging
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

	hostClientSet, hostClientSetErr := NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Host.Credentials, cfg.HonourServiceAccountRefHostCluster, cfg.Controllers.Terminal.TokenRequestExpirationSeconds, r.Scheme)
	targetClientSet, targetClientSetErr := NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Target.Credentials, cfg.HonourServiceAccountRefTargetCluster, cfg.Controllers.Terminal.TokenRequestExpirationSeconds, r.Scheme)

	if !t.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is being deleted
		finalizers := sets.NewString(t.Finalizers...)

		if finalizers.Has(extensionsv1alpha1.TerminalName) {
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
			finalizers.Delete(extensionsv1alpha1.TerminalName)
			t.Finalizers = finalizers.List()

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

	err = r.ensureAdmissionWebhookConfigured(ctx, gardenClientSet, t)
	if err != nil {
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

func (r *TerminalReconciler) ensureAdmissionWebhookConfigured(ctx context.Context, gardenClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	webhookConfigurationOptions := metav1.ListOptions{}
	webhookConfigurationOptions.LabelSelector = labels.SelectorFromSet(map[string]string{
		"terminal": "admission-configuration",
	}).String()

	mutatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
	if err != nil {
		return errors.New(err.Error())
	}

	if len(mutatingWebhookConfigurations.Items) != 1 {
		err := deleteObj(ctx, gardenClientSet, t)
		if err != nil {
			return err
		}

		return fmt.Errorf("expected 1 MutatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(mutatingWebhookConfigurations.Items))
	}

	mutatingWebhookConfiguration := mutatingWebhookConfigurations.Items[0]
	if mutatingWebhookConfiguration.ObjectMeta.CreationTimestamp.After(t.ObjectMeta.CreationTimestamp.Time) {
		err := deleteObj(ctx, gardenClientSet, t)
		if err != nil {
			return err
		}

		return fmt.Errorf("terminal %s has been created before mutating webhook was configured. Deleting resource", t.ObjectMeta.Name)
	}

	validatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
	if err != nil {
		return errors.New(err.Error())
	}

	if len(validatingWebhookConfigurations.Items) != 1 {
		err := deleteObj(ctx, gardenClientSet, t)
		if err != nil {
			return err
		}

		return fmt.Errorf("expected 1 ValidatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(validatingWebhookConfigurations.Items))
	}

	validatingWebhookConfiguration := validatingWebhookConfigurations.Items[0]
	if validatingWebhookConfiguration.ObjectMeta.CreationTimestamp.After(t.ObjectMeta.CreationTimestamp.Time) {
		err := deleteObj(ctx, gardenClientSet, t)
		if err != nil {
			return err
		}

		return fmt.Errorf("terminal %s has been created before validating webhook was configured. Deleting resource", t.ObjectMeta.Name)
	}

	return nil
}

// deleteExternalDependency deletes external dependencies on target and host cluster. In case of an error on the target cluster (e.g. api server cannot be reached) the dependencies on the host cluster are still tried to delete.
func (r *TerminalReconciler) deleteExternalDependency(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) []*extensionsv1alpha1.LastError {
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

func (r *TerminalReconciler) deleteTargetClusterDependencies(ctx context.Context, targetClientSet *ClientSet, t *extensionsv1alpha1.Terminal) *extensionsv1alpha1.LastError {
	if targetClientSet != nil {
		if err := r.deleteAccessToken(ctx, targetClientSet, t); err != nil {
			return formatError("Failed to delete access token", err)
		}
	} else {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in target cluster for terminal identifier: %s", t.Spec.Identifier)
	}

	return nil
}

func (r *TerminalReconciler) deleteHostClusterDependencies(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) *extensionsv1alpha1.LastError {
	if hostClientSet != nil {
		if err := deleteAttachPodSecret(ctx, hostClientSet, t); err != nil {
			return formatError("Failed to delete attach pod secret", err)
		}

		if err := deleteTerminalPod(ctx, hostClientSet, t); err != nil {
			return formatError("Failed to delete terminal pod", err)
		}

		if err := deleteKubeconfigSecret(ctx, hostClientSet, t); err != nil {
			return formatError("failed to delete kubeconfig secret for target cluster", err)
		}

		if err := deleteTokenSecret(ctx, hostClientSet, t); err != nil {
			return formatError("failed to delete token secret for target cluster", err)
		}

		if t.Spec.Host.TemporaryNamespace {
			if err := deleteNamespace(ctx, hostClientSet, *t.Spec.Host.Namespace); err != nil {
				return formatError("failed to delete temporary namespace on host cluster", err)
			}
		}
	} else {
		r.recordEventAndLog(ctx, t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in host cluster for terminal identifier: %s", t.Spec.Identifier)
	}

	return nil
}

func (r *TerminalReconciler) deleteAccessToken(ctx context.Context, targetClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
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

		err := deleteBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, roleBinding)
		if err != nil {
			return err
		}
	}

	if t.Spec.Target.Authorization != nil {
		for _, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
			err := deleteBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, &roleBinding)
			if err != nil {
				return err
			}
		}

		if r.getConfig().HonourProjectMemberships {
			for _, projectMembership := range t.Spec.Target.Authorization.ProjectMemberships {
				if projectMembership.ProjectName != "" && len(projectMembership.Roles) > 0 {
					err := r.removeServiceAccountFromProjectMember(ctx, targetClientSet, projectMembership, serviceAccount)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	if err := deleteObj(ctx, targetClientSet, serviceAccount); err != nil {
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

	if t.Spec.Target.TemporaryNamespace {
		if err := deleteNamespace(ctx, targetClientSet, *t.Spec.Target.Namespace); err != nil {
			return err
		}
	}

	return nil
}

func (r *TerminalReconciler) removeServiceAccountFromProjectMember(ctx context.Context, targetClientSet *ClientSet, projectMembership extensionsv1alpha1.ProjectMembership, serviceAccount *corev1.ServiceAccount) error {
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

	isProjectMember, index := isMember(project.Spec.Members, serviceAccount)
	if !isProjectMember {
		// already removed
		return nil
	}

	// remove member at index
	project.Spec.Members = append(project.Spec.Members[:index], project.Spec.Members[index+1:]...)

	if err := targetClientSet.Update(ctx, project); err != nil {
		return err
	}

	return nil
}

func isMember(members []gardencorev1beta1.ProjectMember, serviceAccount *corev1.ServiceAccount) (bool, int) {
	for index, member := range members {
		isServiceAccountKindMember := member.APIGroup == "" && member.Kind == rbacv1.ServiceAccountKind && member.Namespace == serviceAccount.Namespace && member.Name == serviceAccount.Name
		isUserKindMember := member.APIGroup == rbacv1.GroupName && member.Kind == rbacv1.UserKind && member.Name == "system:serviceaccount:"+serviceAccount.Namespace+":"+serviceAccount.Name
		isMember := isServiceAccountKindMember || isUserKindMember

		if isMember {
			return true, index
		}
	}

	return false, -1
}

func deleteBinding(ctx context.Context, targetClientSet *ClientSet, identifier string, namespace string, roleBinding *extensionsv1alpha1.RoleBinding) error {
	bindingName := extensionsv1alpha1.TerminalAccessResourceNamePrefix + identifier + roleBinding.NameSuffix

	var err error

	switch roleBinding.BindingKind {
	case extensionsv1alpha1.BindingKindClusterRoleBinding:
		err = deleteClusterRoleBinding(ctx, targetClientSet, bindingName)
	case extensionsv1alpha1.BindingKindRoleBinding:
		err = deleteRoleBinding(ctx, targetClientSet, namespace, bindingName)
	default:
		panic("unknown BindingKind " + roleBinding.BindingKind) // should not happen; is validated in webhook
	}

	if err != nil {
		return err
	}

	return nil
}

func deleteAttachPodSecret(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	if err := deleteRoleBinding(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier); err != nil {
		return err
	}

	if err := deleteServiceAccount(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier); err != nil {
		return err
	}

	return deleteRole(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachRoleResourceNamePrefix+t.Spec.Identifier)
}

func (r *TerminalReconciler) reconcileTerminal(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) *extensionsv1alpha1.LastError {
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

func (r *TerminalReconciler) createOrUpdateAttachPodSecret(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) error {
	if t.Spec.Host.TemporaryNamespace {
		if _, err := createOrUpdateNamespace(ctx, hostClientSet, *t.Spec.Host.Namespace, labelSet, annotationSet); err != nil {
			return err
		}
	}

	attachPodServiceAccount, err := createOrUpdateServiceAccount(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, labelSet, annotationSet)
	if err != nil {
		return err
	}

	err = r.updateTerminalStatusAttachServiceAccountName(ctx, t, attachPodServiceAccount.Name)
	if err != nil {
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

	attachRole, err := createOrUpdateAttachRole(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachRoleResourceNamePrefix+t.Spec.Identifier, rules)
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

	_, err = createOrUpdateRoleBinding(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, subject, roleRef, labelSet, annotationSet)
	if err != nil {
		return err
	}

	return nil
}

func (r *TerminalReconciler) updateTerminalStatusAttachServiceAccountName(ctx context.Context, t *extensionsv1alpha1.Terminal, attachServiceAccountName string) error {
	terminal := &extensionsv1alpha1.Terminal{}

	// make sure to fetch the latest version of the terminal resource before updating it's status
	err := r.Get(ctx, client.ObjectKey{Name: t.Name, Namespace: t.Namespace}, terminal)
	if err != nil {
		return err
	}

	terminal.Status.AttachServiceAccountName = attachServiceAccountName

	return r.Status().Update(ctx, terminal)
}

func (r *TerminalReconciler) updateTerminalStatusPodName(ctx context.Context, t *extensionsv1alpha1.Terminal, podName string) error {
	terminal := &extensionsv1alpha1.Terminal{}

	// make sure to fetch the latest version of the terminal resource before updating it's status
	err := r.Get(ctx, client.ObjectKey{Name: t.Name, Namespace: t.Namespace}, terminal)
	if err != nil {
		return err
	}

	terminal.Status.PodName = podName

	return r.Status().Update(ctx, terminal)
}

func createOrUpdateAttachRole(ctx context.Context, hostClientSet *ClientSet, namespace string, name string, rules []rbacv1.PolicyRule) (*rbacv1.Role, error) {
	attachRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return attachRole, CreateOrUpdateDiscardResult(ctx, hostClientSet, attachRole, func() error {
		attachRole.Labels = labels.Merge(attachRole.Labels, labels.Set{extensionsv1alpha1.Component: extensionsv1alpha1.TerminalComponent})

		attachRole.Rules = rules
		return nil
	})
}

func deleteRole(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return deleteObj(ctx, cs, role)
}

func createOrUpdateNamespace(ctx context.Context, cs *ClientSet, namespaceName string, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return ns, CreateOrUpdateDiscardResult(ctx, cs, ns, func() error {
		ns.Labels = labels.Merge(ns.Labels, *labelSet)
		ns.Annotations = utils.MergeStringMap(ns.Annotations, *annotationSet)
		return nil
	})
}

func deleteNamespace(ctx context.Context, cs *ClientSet, namespaceName string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return deleteObj(ctx, cs, ns)
}

func createOrUpdateServiceAccount(ctx context.Context, cs *ClientSet, namespace string, name string, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.ServiceAccount, error) {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return serviceAccount, CreateOrUpdateDiscardResult(ctx, cs, serviceAccount, func() error {
		serviceAccount.Labels = labels.Merge(serviceAccount.Labels, *labelSet)
		serviceAccount.Annotations = utils.MergeStringMap(serviceAccount.Annotations, *annotationSet)
		return nil
	})
}

func deleteServiceAccount(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return deleteObj(ctx, cs, serviceAccount)
}

func createOrUpdateRoleBinding(ctx context.Context, cs *ClientSet, namespace string, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelSet *labels.Set, annotationSet *utils.Set) (*rbacv1.RoleBinding, error) {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return roleBinding, CreateOrUpdateDiscardResult(ctx, cs, roleBinding, func() error {
		roleBinding.Labels = labels.Merge(roleBinding.Labels, *labelSet)
		roleBinding.Annotations = utils.MergeStringMap(roleBinding.Annotations, *annotationSet)

		roleBinding.Subjects = []rbacv1.Subject{subject}
		roleBinding.RoleRef = roleRef

		return nil
	})
}

func deleteRoleBinding(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return deleteObj(ctx, cs, roleBinding)
}

func createOrUpdateClusterRoleBinding(ctx context.Context, cs *ClientSet, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelSet *labels.Set, annotationSet *utils.Set) (*rbacv1.ClusterRoleBinding, error) {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return clusterRoleBinding, CreateOrUpdateDiscardResult(ctx, cs, clusterRoleBinding, func() error {
		clusterRoleBinding.Labels = labels.Merge(clusterRoleBinding.Labels, *labelSet)
		clusterRoleBinding.Annotations = utils.MergeStringMap(clusterRoleBinding.Annotations, *annotationSet)

		clusterRoleBinding.Subjects = []rbacv1.Subject{subject}
		clusterRoleBinding.RoleRef = roleRef

		return nil
	})
}

func deleteClusterRoleBinding(ctx context.Context, cs *ClientSet, name string) error {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return deleteObj(ctx, cs, clusterRoleBinding)
}

type volumeSourceSecretNames struct {
	kubeconfig string
	token      string
}

func (r *TerminalReconciler) createOrUpdateAdminKubeconfigAndTokenSecrets(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) (*volumeSourceSecretNames, error) {
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

func (r *TerminalReconciler) createOrUpdateAccessServiceAccountAndRequestToken(ctx context.Context, targetClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) (string, error) {
	if t.Spec.Target.TemporaryNamespace {
		if _, err := createOrUpdateNamespace(ctx, targetClientSet, *t.Spec.Target.Namespace, labelSet, annotationSet); err != nil {
			return "", err
		}
	}

	accessServiceAccountAnnotations := utils.MergeStringMap(*annotationSet, map[string]string{
		extensionsv1alpha1.Description: "Temporary service account for web-terminal session. Managed by gardener/terminal-controller-manager",
	})

	accessServiceAccount, err := createOrUpdateServiceAccount(ctx, targetClientSet, *t.Spec.Target.Namespace, extensionsv1alpha1.TerminalAccessResourceNamePrefix+t.Spec.Identifier, labelSet, &accessServiceAccountAnnotations)
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

		err := createOrUpdateBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, roleBinding, labelSet, annotationSet, accessServiceAccount)
		if err != nil {
			return "", err
		}
	}

	if t.Spec.Target.Authorization != nil {
		for _, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
			err := createOrUpdateBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, &roleBinding, labelSet, annotationSet, accessServiceAccount)
			if err != nil {
				return "", err
			}
		}

		if r.getConfig().HonourProjectMemberships {
			for _, projectMembership := range t.Spec.Target.Authorization.ProjectMemberships {
				if projectMembership.ProjectName != "" && len(projectMembership.Roles) > 0 {
					err := addServiceAccountAsProjectMember(ctx, targetClientSet, projectMembership, accessServiceAccount)
					if err != nil {
						return "", err
					}
				}
			}
		}
	}

	childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return requestToken(childCtx, targetClientSet, accessServiceAccount, r.getConfig().Controllers.Terminal.TokenRequestExpirationSeconds)
}

func addServiceAccountAsProjectMember(ctx context.Context, targetClientSet *ClientSet, projectMembership extensionsv1alpha1.ProjectMembership, serviceAccount *corev1.ServiceAccount) error {
	project := &gardencorev1beta1.Project{}
	if err := targetClientSet.Get(ctx, client.ObjectKey{Name: projectMembership.ProjectName}, project); err != nil {
		return err
	}

	isProjectMember, _ := isMember(project.Spec.Members, serviceAccount)
	if isProjectMember {
		// will not attempt to update
		return nil
	}

	member := gardencorev1beta1.ProjectMember{
		Subject: rbacv1.Subject{
			APIGroup:  "",
			Kind:      rbacv1.ServiceAccountKind,
			Name:      serviceAccount.Name,
			Namespace: serviceAccount.Namespace,
		},
	}

	member.Role = projectMembership.Roles[0]

	if len(projectMembership.Roles) > 1 {
		member.Roles = projectMembership.Roles[1:]
	} else {
		member.Roles = nil
	}

	project.Spec.Members = append(project.Spec.Members, member)

	if err := targetClientSet.Update(ctx, project); err != nil {
		return err
	}

	return nil
}

func createOrUpdateBinding(ctx context.Context, targetClientSet *ClientSet, identifier string, namespace string, roleBinding *extensionsv1alpha1.RoleBinding, labelSet *labels.Set, annotationSet *utils.Set, accessServiceAccount *corev1.ServiceAccount) error {
	subject := rbacv1.Subject{
		Kind:      rbacv1.ServiceAccountKind,
		Namespace: accessServiceAccount.Namespace,
		Name:      accessServiceAccount.Name,
	}
	bindingName := extensionsv1alpha1.TerminalAccessResourceNamePrefix + identifier + roleBinding.NameSuffix

	var err error

	switch roleBinding.BindingKind {
	case extensionsv1alpha1.BindingKindClusterRoleBinding:
		_, err = createOrUpdateClusterRoleBinding(ctx, targetClientSet, bindingName, subject, roleBinding.RoleRef, labelSet, annotationSet)
	case extensionsv1alpha1.BindingKindRoleBinding:
		_, err = createOrUpdateRoleBinding(ctx, targetClientSet, namespace, bindingName, subject, roleBinding.RoleRef, labelSet, annotationSet)
	default:
		panic("unknown BindingKind " + roleBinding.BindingKind) // should not happen; is validated in webhook
	}

	if err != nil {
		return err
	}

	return nil
}

// requestToken requests a token using the TokenRequest API for the given service account
func requestToken(ctx context.Context, cs *ClientSet, serviceAccount *corev1.ServiceAccount, expirationSeconds *int64) (string, error) {
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: expirationSeconds,
		},
	}

	tokenRequest, err := cs.Kubernetes.CoreV1().ServiceAccounts(serviceAccount.Namespace).CreateToken(ctx, serviceAccount.Name, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	return tokenRequest.Status.Token, nil
}

// WaitUntilTokenAvailable waits until the secret that is referenced in the service account exists and returns it.
func WaitUntilTokenAvailable(ctx context.Context, cs *ClientSet, serviceAccount *corev1.ServiceAccount) (*corev1.Secret, error) {
	fieldSelector := fields.SelectorFromSet(map[string]string{
		"metadata.name": serviceAccount.Name,
	}).String()

	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return cs.Kubernetes.CoreV1().ServiceAccounts(serviceAccount.Namespace).List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return cs.Kubernetes.CoreV1().ServiceAccounts(serviceAccount.Namespace).Watch(ctx, options)
		},
	}

	event, err := watchtools.UntilWithSync(ctx, lw, &corev1.ServiceAccount{}, nil,
		func(event watch.Event) (bool, error) {
			switch event.Type {
			case watch.Deleted:
				return false, nil
			case watch.Error:
				return false, fmt.Errorf("error watching")

			case watch.Added, watch.Modified:
				watchedSa, ok := event.Object.(*corev1.ServiceAccount)
				if !ok {
					return false, fmt.Errorf("unexpected object type: %T", event.Object)
				}
				if len(watchedSa.Secrets) == 0 {
					return false, nil
				}
				return true, nil

			default:
				return false, fmt.Errorf("unexpected event type: %v", event.Type)
			}
		})

	if err != nil {
		return nil, fmt.Errorf("unable to read secret from service account: %v", err)
	}

	watchedSa, _ := event.Object.(*corev1.ServiceAccount)
	secretRef := watchedSa.Secrets[0]

	secret := &corev1.Secret{}

	return secret, cs.Get(ctx, client.ObjectKey{Namespace: serviceAccount.Namespace, Name: secretRef.Name}, secret)
}

func clusterNameForCredential(cred extensionsv1alpha1.ClusterCredentials) (string, error) {
	if cred.ShootRef != nil {
		return cred.ShootRef.Name, nil
	} else if cred.SecretRef != nil {
		return cred.SecretRef.Name, nil
	} else if cred.ServiceAccountRef != nil {
		return cred.ServiceAccountRef.Name, nil
	} else {
		return "", errors.New("no cluster credentials provided")
	}
}

func createOrUpdateKubeconfigSecret(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Secret, error) {
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
		if err := hostClientSet.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &corev1.Service{}); err != nil {
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
		DataKeyKubeConfig: kubeconfig,
	}

	return createOrUpdateSecretData(ctx, hostClientSet, *t.Spec.Host.Namespace, kubeconfigSecretName, data, labelSet, annotationSet)
}

func createOrUpdateServiceAccountTokenSecret(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, token string, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Secret, error) {
	secretName := extensionsv1alpha1.TokenSecretResourceNamePrefix + t.Spec.Identifier

	data := map[string][]byte{
		DataKeyToken: []byte(token),
	}

	return createOrUpdateSecretData(ctx, hostClientSet, *t.Spec.Host.Namespace, secretName, data, labelSet, annotationSet)
}

func deleteKubeconfigSecret(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	kubeconfigSecretName := extensionsv1alpha1.KubeconfigSecretResourceNamePrefix + t.Spec.Identifier
	return deleteSecret(ctx, hostClientSet, *t.Spec.Host.Namespace, kubeconfigSecretName)
}

func deleteTokenSecret(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	kubeconfigSecretName := extensionsv1alpha1.TokenSecretResourceNamePrefix + t.Spec.Identifier
	return deleteSecret(ctx, hostClientSet, *t.Spec.Host.Namespace, kubeconfigSecretName)
}

func createOrUpdateSecretData(ctx context.Context, cs *ClientSet, namespace string, name string, data map[string][]byte, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Secret, error) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return secret, CreateOrUpdateDiscardResult(ctx, cs, secret, func() error {
		secret.Labels = labels.Merge(secret.Labels, *labelSet)
		secret.Annotations = utils.MergeStringMap(secret.Annotations, *annotationSet)

		secret.Data = data
		secret.Type = corev1.SecretTypeOpaque

		return nil
	})
}

func deleteSecret(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return deleteObj(ctx, cs, secret)
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

func (r *TerminalReconciler) createOrUpdateTerminalPod(ctx context.Context, cs *ClientSet, t *extensionsv1alpha1.Terminal, secretNames *volumeSourceSecretNames, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Pod, error) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: *t.Spec.Host.Namespace, Name: extensionsv1alpha1.TerminalPodResourceNamePrefix + t.Spec.Identifier}}

	const (
		containerName                 = "terminal"
		initContainerName             = "setup"
		kubeconfigReadWriteVolumeName = "kubeconfig-rw"
		kubeconfigReadOnlyVolumeName  = "kubeconfig"
		tokenVolumeName               = "token"
	)

	err := r.updateTerminalStatusPodName(ctx, t, pod.Name)
	if err != nil {
		return nil, err
	}

	return pod, CreateOrUpdateDiscardResult(ctx, cs, pod, func() error {
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
					MountPath: "/hostroot",
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
									Key:  DataKeyKubeConfig,
									Path: "config",
								},
							},
						},
					},
				},
				{
					Name: kubeconfigReadWriteVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumDefault}},
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
		var containerFound bool
		var containerIndex int
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
			masterNodeKey := "node-role.kubernetes.io/master"
			criticalAddonsKey := "CriticalAddonsOnly"
			if !tolerationExists(pod.Spec.Tolerations, matchByKey(masterNodeKey)) {
				pod.Spec.Tolerations = append(pod.Spec.Tolerations,
					corev1.Toleration{
						Key:      masterNodeKey,
						Operator: corev1.TolerationOpExists,
						Effect:   corev1.TaintEffectNoSchedule,
					})
			}
			if !tolerationExists(pod.Spec.Tolerations, matchByKey(criticalAddonsKey)) {
				pod.Spec.Tolerations = append(pod.Spec.Tolerations,
					corev1.Toleration{
						Key:      criticalAddonsKey,
						Operator: corev1.TolerationOpExists,
					})
			}

			noExecuteToleration := corev1.Toleration{
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoExecute,
			}
			if !tolerationExists(pod.Spec.Tolerations, match(noExecuteToleration)) {
				pod.Spec.Tolerations = append(pod.Spec.Tolerations, noExecuteToleration)
			}
		}

		return nil
	})
}

func deleteTerminalPod(ctx context.Context, cs *ClientSet, t *extensionsv1alpha1.Terminal) error {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: *t.Spec.Host.Namespace, Name: extensionsv1alpha1.TerminalPodResourceNamePrefix + t.Spec.Identifier}}

	return deleteObj(ctx, cs, pod)
}

func deleteObj(ctx context.Context, cs *ClientSet, obj client.Object) error {
	err := cs.Delete(ctx, obj)
	if kErros.IsNotFound(err) {
		return nil
	}

	return err
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

func NewClientSet(config *rest.Config, client client.Client, kubernetes kubernetes.Interface) *ClientSet {
	return &ClientSet{config, client, kubernetes}
}

func NewClientSetFromClusterCredentials(ctx context.Context, cs *ClientSet, credentials extensionsv1alpha1.ClusterCredentials, honourServiceAccountRef bool, expirationSeconds *int64, scheme *runtime.Scheme) (*ClientSet, error) {
	if credentials.ShootRef != nil {
		return NewClientSetFromShootRef(ctx, cs, credentials.ShootRef, scheme)
	} else if credentials.SecretRef != nil {
		return NewClientSetFromSecretRef(ctx, cs, credentials.SecretRef, scheme)
	} else if honourServiceAccountRef && credentials.ServiceAccountRef != nil {
		return NewClientSetFromServiceAccountRef(ctx, cs, credentials.ServiceAccountRef, expirationSeconds, scheme)
	} else {
		return nil, errors.New("no cluster credentials provided")
	}
}

func NewClientSetFromServiceAccountRef(ctx context.Context, cs *ClientSet, ref *corev1.ObjectReference, expirationSeconds *int64, scheme *runtime.Scheme) (*ClientSet, error) {
	serviceAccount := &corev1.ServiceAccount{}
	if err := cs.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, serviceAccount); err != nil {
		return nil, err
	}

	token, err := requestToken(ctx, cs, serviceAccount, expirationSeconds)
	if err != nil {
		return nil, err
	}

	caData, err := utils.DataFromSliceOrFile(cs.Config.CAData, cs.Config.CAFile)
	if err != nil {
		return nil, err
	}

	secretConfig := &rest.Config{
		Host: cs.Config.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caData,
		},
		BearerToken: token,
	}

	return NewClientSetForConfig(secretConfig, client.Options{
		Scheme: scheme,
	})
}

func NewClientSetFromShootRef(ctx context.Context, cs *ClientSet, ref *extensionsv1alpha1.ShootRef, scheme *runtime.Scheme) (*ClientSet, error) {
	expirationSeconds := int64((10 * time.Minute).Seconds()) // lowest possible value https://github.com/gardener/gardener/blob/master/pkg/apis/authentication/validation/validation.go#L34
	adminKubeconfigRequest := &authenticationv1alpha1.AdminKubeconfigRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdminKubeconfigRequest",
			APIVersion: authenticationv1alpha1.SchemeGroupVersion.String(),
		},
		Spec: authenticationv1alpha1.AdminKubeconfigRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	gardenCore, err := gardencoreclientset.NewForConfig(cs.Config)
	if err != nil {
		return nil, err
	}

	result := &authenticationv1alpha1.AdminKubeconfigRequest{}

	err = gardenCore.CoreV1beta1().RESTClient().Post().
		Namespace(ref.Namespace).
		Resource("shoots").
		Name(ref.Name).
		SubResource("adminkubeconfig").
		VersionedParams(&metav1.CreateOptions{}, gardenscheme.ParameterCodec).
		Body(adminKubeconfigRequest).
		Do(ctx).
		Into(result)
	if err != nil {
		return nil, err
	}

	return NewClientSetFromBytes(result.Status.Kubeconfig, client.Options{
		Scheme: scheme,
	})
}

func NewClientSetFromSecretRef(ctx context.Context, cs *ClientSet, ref *corev1.SecretReference, scheme *runtime.Scheme) (*ClientSet, error) {
	secret := &corev1.Secret{}
	if err := cs.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		return nil, err
	}

	return NewClientSetFromSecret(ctx, cs.Config, secret, client.Options{
		Scheme: scheme,
	})
}

// NewClientSetFromSecret creates a new controller ClientSet struct for a given secret.
// Client is created either from "kubeconfig" (and in case of gcp from "serviceaccount.json") or "token" and "ca.crt" data keys
func NewClientSetFromSecret(ctx context.Context, config *rest.Config, secret *corev1.Secret, opts client.Options) (*ClientSet, error) {
	if kubeconfig, ok := secret.Data[DataKeyKubeConfig]; ok {
		clientConfig, err := clientcmd.NewClientConfigFromBytes(kubeconfig)
		if err != nil {
			return nil, err
		}

		cfg, err := clientConfig.RawConfig()
		if err != nil {
			return nil, err
		}

		context := cfg.Contexts[cfg.CurrentContext]
		if context == nil {
			return nil, fmt.Errorf("no context found for current context %s", cfg.CurrentContext)
		}

		authInfo := cfg.AuthInfos[context.AuthInfo]
		if authInfo == nil {
			return nil, fmt.Errorf("no auth info found with name %s", context.AuthInfo)
		}

		if authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "gcp" {
			gsaKey, ok := secret.Data[DataKeyServiceaccountJSON]
			if !ok {
				return nil, fmt.Errorf("%q required in secret for gcp authentication provider", DataKeyServiceaccountJSON)
			}

			return NewClientSetFromGoogleSAKey(ctx, cfg, *context, gsaKey, opts)
		}

		return NewClientSetFromBytes(kubeconfig, opts)
	}

	if token, ok := secret.Data[corev1.ServiceAccountTokenKey]; ok {
		secretConfig := &rest.Config{
			Host: config.Host,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: secret.Data[corev1.ServiceAccountRootCAKey],
			},
			BearerToken: string(token),
		}

		return NewClientSetForConfig(secretConfig, opts)
	}

	return nil, errors.New("no valid kubeconfig found")
}

// NewClientSetFromGoogleSAKey creates a new controller ClientSet struct for a given google service account key and client config.
func NewClientSetFromGoogleSAKey(ctx context.Context, cfg clientcmdapi.Config, context clientcmdapi.Context, gsaKey []byte, opts client.Options) (*ClientSet, error) {
	cluster := cfg.Clusters[context.Cluster]
	if cluster == nil {
		return nil, fmt.Errorf("no cluster found with name %s", context.Cluster)
	}

	// defaultScopes:
	// - cloud-platform is the base scope to authenticate to GCP
	defaultScopes := []string{
		"https://www.googleapis.com/auth/cloud-platform",
	}

	credentials, err := google.CredentialsFromJSON(ctx, gsaKey, defaultScopes...)
	if err != nil {
		return nil, fmt.Errorf("could not get google credentials from json: %w", err)
	}

	token, err := credentials.TokenSource.Token()
	if err != nil {
		return nil, err
	}

	secretConfig := &rest.Config{
		Host: cluster.Server,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: cluster.CertificateAuthorityData,
		},
		BearerToken: token.AccessToken,
	}

	return NewClientSetForConfig(secretConfig, opts)
}

func CreateOrUpdateDiscardResult(ctx context.Context, cs *ClientSet, obj client.Object, f controllerutil.MutateFn) error {
	_, err := ctrl.CreateOrUpdate(ctx, cs.Client, obj, f)
	return err
}

// code below copied from gardener/gardener

// TODO move to utils
func formatError(message string, err error) *extensionsv1alpha1.LastError {
	return &extensionsv1alpha1.LastError{
		Description: fmt.Sprintf("%s (%s)", message, err.Error()),
	}
}

const (
	// DataKeyKubeConfig is the key in a secret holding the kubeconfig
	DataKeyKubeConfig = "kubeconfig"
	// DataKeyToken is the key in a secret holding the token
	DataKeyToken = "token"
	// DataKeyServiceaccountJSON is the key in a secret data holding the google service account key.
	DataKeyServiceaccountJSON = "serviceaccount.json"
)

// NewClientSetFromBytes creates a new controller ClientSet struct for a given kubeconfig byte slice.
func NewClientSetFromBytes(kubeconfig []byte, opts client.Options) (*ClientSet, error) {
	clientConfig, err := clientcmd.NewClientConfigFromBytes(kubeconfig)
	if err != nil {
		return nil, err
	}

	// Validate that the given kubeconfig doesn't have fields in its auth-info that are not acceptable.
	rawConfig, err := clientConfig.RawConfig()
	if err != nil {
		return nil, err
	}

	if err := ValidateClientConfig(rawConfig); err != nil {
		return nil, err
	}

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	return NewClientSetForConfig(config, opts)
}

// NewClientSetForConfig returns a new controller ClientSet struct from a config.
func NewClientSetForConfig(config *rest.Config, opts client.Options) (*ClientSet, error) {
	client, err := client.New(config, opts)
	if err != nil {
		return nil, err
	}

	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &ClientSet{config, client, kube}, err
}

// ValidateClientConfig validates that the auth info of a given kubeconfig doesn't have unsupported fields.
func ValidateClientConfig(config clientcmdapi.Config) error {
	validFields := []string{"client-certificate-data", "client-key-data", "token", "username", "password"}

	for user, authInfo := range config.AuthInfos {
		switch {
		case authInfo.ClientCertificate != "":
			return fmt.Errorf("client certificate files are not supported (user %q), these are the valid fields: %+v", user, validFields)
		case authInfo.ClientKey != "":
			return fmt.Errorf("client key files are not supported (user %q), these are the valid fields: %+v", user, validFields)
		case authInfo.TokenFile != "":
			return fmt.Errorf("token files are not supported (user %q), these are the valid fields: %+v", user, validFields)
		case authInfo.Impersonate != "" || len(authInfo.ImpersonateGroups) > 0:
			return fmt.Errorf("impersonation is not supported, these are the valid fields: %+v", validFields)
		case authInfo.AuthProvider != nil && len(authInfo.AuthProvider.Config) > 0:
			return fmt.Errorf("auth provider configurations are not supported (user %q), these are the valid fields: %+v", user, validFields)
		case authInfo.Exec != nil:
			return fmt.Errorf("exec configurations are not supported (user %q), these are the valid fields: %+v", user, validFields)
		}
	}

	return nil
}
