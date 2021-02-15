/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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

	"github.com/gardener/terminal-controller-manager/utils"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/controller"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kErros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	watchtools "k8s.io/client-go/tools/watch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	extensionsv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
)

// TerminalReconciler reconciles a Terminal object
type TerminalReconciler struct {
	Scheme *runtime.Scheme
	*ClientSet
	Recorder                    record.EventRecorder
	Log                         logr.Logger
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
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups=dashboard.gardener.cloud,resources=terminals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dashboard.gardener.cloud,resources=terminals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.gardener.cloud,resources=projects,verbs=get;list;watch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations;mutatingwebhookconfigurations,verbs=list

func (r *TerminalReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if err := r.increaseCounterForNamespace(req.Namespace); err != nil {
		r.Log.Info("maximum parallel reconciles reached for namespace - requeuing the req", "namespace", req.Namespace, "name", req.Name)

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

	hostClientSet, hostClientSetErr := NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Host.Credentials, r.getConfig().HonourServiceAccountRefHostCluster, r.Scheme)
	targetClientSet, targetClientSetErr := NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Target.Credentials, r.getConfig().HonourServiceAccountRefTargetCluster, r.Scheme)

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

			r.recordEventAndLog(t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleting, "Deleting external dependencies")
			// our finalizer is present, so lets handle our external dependency

			if deletionErrors := r.deleteExternalDependency(ctx, targetClientSet, hostClientSet, t); deletionErrors != nil {
				var errStrings []string
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				for _, deletionErr := range deletionErrors {
					r.recordEventAndLog(t, corev1.EventTypeWarning, extensionsv1alpha1.EventDeleteError, deletionErr.Description)
					errStrings = append(errStrings, deletionErr.Description)
				}

				return ctrl.Result{}, errors.New(strings.Join(errStrings, "\n"))
			}

			r.recordEventAndLog(t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleted, "Deleted external dependencies")

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
		r.recordEventAndLog(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, err.Error())
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

	labelsSet, err := t.NewLabelsSet()
	if err != nil {
		// the needed labels will be set eventually, requeue won't change that
		r.recordEventAndLog(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, "Transient problem - %s. Skipping...", err.Error())

		return ctrl.Result{}, nil
	}

	annotationsSet, err := t.NewAnnotationsSet()
	if err != nil {
		// the needed annotations will be set eventually, requeue won't change that
		r.recordEventAndLog(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, "Transient problem - %s. Skipping...", err.Error())

		return ctrl.Result{}, nil
	}

	r.recordEventAndLog(t, corev1.EventTypeNormal, extensionsv1alpha1.EventReconciling, "Reconciling Terminal state")

	if err := r.reconcileTerminal(ctx, targetClientSet, hostClientSet, t, labelsSet, annotationsSet); err != nil {
		r.recordEventAndLog(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, err.Description)
		return ctrl.Result{}, errors.New(err.Description)
	}

	r.recordEventAndLog(t, corev1.EventTypeNormal, extensionsv1alpha1.EventReconciled, "Reconciled Terminal state")

	return ctrl.Result{}, nil
}

func (r *TerminalReconciler) recordEventAndLog(t *extensionsv1alpha1.Terminal, eventType, reason, messageFmt string, args ...interface{}) {
	r.Recorder.Eventf(t, eventType, reason, messageFmt, args...)
	r.Log.Info(fmt.Sprintf(messageFmt, args...), "namespace", t.Namespace, "name", t.Name)
}

func (r *TerminalReconciler) ensureAdmissionWebhookConfigured(ctx context.Context, gardenClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	webhookConfigurationOptions := metav1.ListOptions{}
	webhookConfigurationOptions.LabelSelector = labels.SelectorFromSet(map[string]string{
		"terminal": "admission-configuration",
	}).String()

	mutatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
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

	validatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().List(ctx, webhookConfigurationOptions)
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
		r.recordEventAndLog(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in target cluster for terminal identifier: %s", t.Spec.Identifier)
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

		if err := deleteKubeconfig(ctx, hostClientSet, t); err != nil {
			return formatError("failed to delete kubeconfig for target cluster", err)
		}

		if t.Spec.Host.TemporaryNamespace {
			if err := deleteNamespace(ctx, hostClientSet, *t.Spec.Host.Namespace); err != nil {
				return formatError("failed to delete temporary namespace on host cluster", err)
			}
		}
	} else {
		r.recordEventAndLog(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in host cluster for terminal identifier: %s", t.Spec.Identifier)
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

func (r *TerminalReconciler) reconcileTerminal(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelsSet *labels.Set, annotationsSet *utils.Set) *extensionsv1alpha1.LastError {
	if err := r.createOrUpdateAttachPodSecret(ctx, hostClientSet, t, labelsSet, annotationsSet); err != nil {
		return formatError("Failed to create or update resources needed for attaching to a pod", err)
	}

	kubeconfigSecret, err := r.createOrUpdateAdminKubeconfig(ctx, targetClientSet, hostClientSet, t, labelsSet, annotationsSet)
	if err != nil {
		return formatError("Failed to create or update admin kubeconfig", err)
	}

	if _, err = r.createOrUpdateTerminalPod(ctx, hostClientSet, t, kubeconfigSecret.Name, labelsSet, annotationsSet); err != nil {
		return formatError("Failed to create or update terminal pod", err)
	}

	return nil
}

func (r *TerminalReconciler) createOrUpdateAttachPodSecret(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelsSet *labels.Set, annotationsSet *utils.Set) error {
	if t.Spec.Host.TemporaryNamespace {
		if _, err := createOrUpdateNamespace(ctx, hostClientSet, *t.Spec.Host.Namespace, labelsSet, annotationsSet); err != nil {
			return err
		}
	}

	attachPodServiceAccount, err := createOrUpdateServiceAccount(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, labelsSet, annotationsSet)
	if err != nil {
		return err
	}

	t.Status.AttachServiceAccountName = attachPodServiceAccount.Name

	err = r.Status().Update(ctx, t)
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

	_, err = createOrUpdateRoleBinding(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, subject, roleRef, labelsSet, annotationsSet)
	if err != nil {
		return err
	}

	return nil
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

func createOrUpdateNamespace(ctx context.Context, cs *ClientSet, namespaceName string, labelsSet *labels.Set, annotationsSet *utils.Set) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return ns, CreateOrUpdateDiscardResult(ctx, cs, ns, func() error {
		ns.Labels = labels.Merge(ns.Labels, *labelsSet)
		ns.Annotations = utils.MergeStringMap(ns.Annotations, *annotationsSet)
		return nil
	})
}

func deleteNamespace(ctx context.Context, cs *ClientSet, namespaceName string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return deleteObj(ctx, cs, ns)
}

func createOrUpdateServiceAccount(ctx context.Context, cs *ClientSet, namespace string, name string, labelsSet *labels.Set, annotationsSet *utils.Set) (*corev1.ServiceAccount, error) {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return serviceAccount, CreateOrUpdateDiscardResult(ctx, cs, serviceAccount, func() error {
		serviceAccount.Labels = labels.Merge(serviceAccount.Labels, *labelsSet)
		serviceAccount.Annotations = utils.MergeStringMap(serviceAccount.Annotations, *annotationsSet)
		return nil
	})
}

func deleteServiceAccount(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return deleteObj(ctx, cs, serviceAccount)
}

func createOrUpdateRoleBinding(ctx context.Context, cs *ClientSet, namespace string, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelsSet *labels.Set, annotationsSet *utils.Set) (*rbacv1.RoleBinding, error) {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return roleBinding, CreateOrUpdateDiscardResult(ctx, cs, roleBinding, func() error {
		roleBinding.Labels = labels.Merge(roleBinding.Labels, *labelsSet)
		roleBinding.Annotations = utils.MergeStringMap(roleBinding.Annotations, *annotationsSet)

		roleBinding.Subjects = []rbacv1.Subject{subject}
		roleBinding.RoleRef = roleRef

		return nil
	})
}

func deleteRoleBinding(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return deleteObj(ctx, cs, roleBinding)
}

func createOrUpdateClusterRoleBinding(ctx context.Context, cs *ClientSet, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelsSet *labels.Set, annotationsSet *utils.Set) (*rbacv1.ClusterRoleBinding, error) {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return clusterRoleBinding, CreateOrUpdateDiscardResult(ctx, cs, clusterRoleBinding, func() error {
		clusterRoleBinding.Labels = labels.Merge(clusterRoleBinding.Labels, *labelsSet)
		clusterRoleBinding.Annotations = utils.MergeStringMap(clusterRoleBinding.Annotations, *annotationsSet)

		clusterRoleBinding.Subjects = []rbacv1.Subject{subject}
		clusterRoleBinding.RoleRef = roleRef

		return nil
	})
}

func deleteClusterRoleBinding(ctx context.Context, cs *ClientSet, name string) error {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return deleteObj(ctx, cs, clusterRoleBinding)
}

func (r *TerminalReconciler) createOrUpdateAdminKubeconfig(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelsSet *labels.Set, annotationsSet *utils.Set) (*corev1.Secret, error) {
	accessSecret, err := r.createAccessToken(ctx, targetClientSet, t, labelsSet, annotationsSet)
	if err != nil {
		return nil, err
	}

	return createOrUpdateKubeconfig(ctx, targetClientSet, hostClientSet, t, accessSecret, labelsSet, annotationsSet)
}

func (r *TerminalReconciler) createAccessToken(ctx context.Context, targetClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelsSet *labels.Set, annotationsSet *utils.Set) (*corev1.Secret, error) {
	if t.Spec.Target.TemporaryNamespace {
		if _, err := createOrUpdateNamespace(ctx, targetClientSet, *t.Spec.Target.Namespace, labelsSet, annotationsSet); err != nil {
			return nil, err
		}
	}

	accessServiceAccountAnnotations := utils.MergeStringMap(*annotationsSet, map[string]string{
		extensionsv1alpha1.Description: "Temporary service account for web-terminal session. Managed by gardener/terminal-controller-manager",
	})

	accessServiceAccount, err := createOrUpdateServiceAccount(ctx, targetClientSet, *t.Spec.Target.Namespace, extensionsv1alpha1.TerminalAccessResourceNamePrefix+t.Spec.Identifier, labelsSet, &accessServiceAccountAnnotations)
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

		err := createOrUpdateBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, roleBinding, labelsSet, annotationsSet, accessServiceAccount)
		if err != nil {
			return nil, err
		}
	}

	if t.Spec.Target.Authorization != nil {
		for _, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
			err := createOrUpdateBinding(ctx, targetClientSet, t.Spec.Identifier, *t.Spec.Target.Namespace, &roleBinding, labelsSet, annotationsSet, accessServiceAccount)
			if err != nil {
				return nil, err
			}
		}

		if r.getConfig().HonourProjectMemberships {
			for _, projectMembership := range t.Spec.Target.Authorization.ProjectMemberships {
				if projectMembership.ProjectName != "" && len(projectMembership.Roles) > 0 {
					err := addServiceAccountAsProjectMember(ctx, targetClientSet, projectMembership, accessServiceAccount)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return WaitUntilTokenAvailable(childCtx, targetClientSet, accessServiceAccount)
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

func createOrUpdateBinding(ctx context.Context, targetClientSet *ClientSet, identifier string, namespace string, roleBinding *extensionsv1alpha1.RoleBinding, labelsSet *labels.Set, annotationsSet *utils.Set, accessServiceAccount *corev1.ServiceAccount) error {
	subject := rbacv1.Subject{
		Kind:      rbacv1.ServiceAccountKind,
		Namespace: accessServiceAccount.Namespace,
		Name:      accessServiceAccount.Name,
	}
	bindingName := extensionsv1alpha1.TerminalAccessResourceNamePrefix + identifier + roleBinding.NameSuffix

	var err error

	switch roleBinding.BindingKind {
	case extensionsv1alpha1.BindingKindClusterRoleBinding:
		_, err = createOrUpdateClusterRoleBinding(ctx, targetClientSet, bindingName, subject, roleBinding.RoleRef, labelsSet, annotationsSet)
	case extensionsv1alpha1.BindingKindRoleBinding:
		_, err = createOrUpdateRoleBinding(ctx, targetClientSet, namespace, bindingName, subject, roleBinding.RoleRef, labelsSet, annotationsSet)
	default:
		panic("unknown BindingKind " + roleBinding.BindingKind) // should not happen; is validated in webhook
	}

	if err != nil {
		return err
	}

	return nil
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
	if cred.SecretRef != nil {
		return cred.SecretRef.Name, nil
	} else if cred.ServiceAccountRef != nil {
		return cred.ServiceAccountRef.Name, nil
	} else {
		return "", errors.New("no cluster credentials provided")
	}
}

func createOrUpdateKubeconfig(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, accessSecret *corev1.Secret, labelsSet *labels.Set, annotationsSet *utils.Set) (*corev1.Secret, error) {
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

	kubeconfig, err := GenerateKubeconfigFromTokenSecret(clusterName, contextNamespace, server, accessSecret)
	if err != nil {
		return nil, err
	}

	kubeconfigSecretName := extensionsv1alpha1.KubeconfigSecretResourceNamePrefix + t.Spec.Identifier

	data := map[string][]byte{
		"kubeconfig": kubeconfig,
	}

	return createOrUpdateSecretData(ctx, hostClientSet, *t.Spec.Host.Namespace, kubeconfigSecretName, data, labelsSet, annotationsSet)
}

func deleteKubeconfig(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	kubeconfigSecretName := extensionsv1alpha1.KubeconfigSecretResourceNamePrefix + t.Spec.Identifier
	return deleteSecret(ctx, hostClientSet, *t.Spec.Host.Namespace, kubeconfigSecretName)
}

func createOrUpdateSecretData(ctx context.Context, cs *ClientSet, namespace string, name string, data map[string][]byte, labelsSet *labels.Set, annotationsSet *utils.Set) (*corev1.Secret, error) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return secret, CreateOrUpdateDiscardResult(ctx, cs, secret, func() error {
		secret.Labels = labels.Merge(secret.Labels, *labelsSet)
		secret.Annotations = utils.MergeStringMap(secret.Annotations, *annotationsSet)

		secret.Data = data
		secret.Type = corev1.SecretTypeOpaque

		return nil
	})
}

func deleteSecret(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return deleteObj(ctx, cs, secret)
}

// GenerateKubeconfigFromTokenSecret generates a kubeconfig using the provided
func GenerateKubeconfigFromTokenSecret(clusterName string, contextNamespace string, server string, secret *corev1.Secret) ([]byte, error) {
	if server == "" {
		return nil, errors.New("api server host is required")
	}

	matched, _ := regexp.MatchString(`^https:\/\/localhost:\d{1,5}$`, server)
	if matched {
		server = "https://kubernetes.default.svc.cluster.local"
	}

	token, ok := secret.Data[corev1.ServiceAccountTokenKey]
	if !ok {
		return nil, errors.New("no " + corev1.ServiceAccountTokenKey + " found on secret")
	}

	kubeConfig := &clientcmdv1.Config{
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
					CertificateAuthorityData: secret.Data[corev1.ServiceAccountRootCAKey],
				},
			},
		},
		AuthInfos: []clientcmdv1.NamedAuthInfo{
			{
				Name: clusterName,
				AuthInfo: clientcmdv1.AuthInfo{
					Token: string(token),
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

	return yaml.Marshal(kubeConfig)
}

func (r *TerminalReconciler) createOrUpdateTerminalPod(ctx context.Context, cs *ClientSet, t *extensionsv1alpha1.Terminal, kubeconfigSecretName string, labelsSet *labels.Set, annotationsSet *utils.Set) (*corev1.Pod, error) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: *t.Spec.Host.Namespace, Name: extensionsv1alpha1.TerminalPodResourceNamePrefix + t.Spec.Identifier}}

	const (
		containerName                 = "terminal"
		initContainerName             = "setup"
		kubeconfigReadWriteVolumeName = "kubeconfig-rw"
		kubeconfigReadOnlyVolumeName  = "kubeconfig"
	)

	t.Status.PodName = pod.Name

	err := r.Status().Update(ctx, t)
	if err != nil {
		return nil, err
	}

	return pod, CreateOrUpdateDiscardResult(ctx, cs, pod, func() error {
		pod.Labels = labels.Merge(pod.Labels, t.Spec.Host.Pod.Labels)
		pod.Labels = labels.Merge(pod.Labels, *labelsSet)
		pod.Annotations = utils.MergeStringMap(pod.Annotations, *annotationsSet)

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

		tolerationExists := func(key string) bool {
			for _, toleration := range pod.Spec.Tolerations {
				if toleration.Key == key {
					return true
				}
			}
			return false
		}

		if len(pod.Spec.Containers) == 0 {
			// initialize values that cannot be updated
			container := corev1.Container{Name: containerName}

			container.VolumeMounts = []corev1.VolumeMount{
				{
					Name:      kubeconfigReadWriteVolumeName,
					MountPath: "mnt/.kube",
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
							SecretName: kubeconfigSecretName,
							Items: []corev1.KeyToPath{
								{
									Key:  "kubeconfig",
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
			tolerationKey := "node-role.kubernetes.io/master"
			if !tolerationExists(tolerationKey) {
				pod.Spec.Tolerations = append(pod.Spec.Tolerations,
					corev1.Toleration{
						Key:      tolerationKey,
						Operator: corev1.TolerationOpExists,
						Effect:   corev1.TaintEffectNoSchedule,
					})
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

func NewClientSet(config *rest.Config, client client.Client, kubernetes kubernetes.Interface) *ClientSet {
	return &ClientSet{config, client, kubernetes}
}

func NewClientSetFromClusterCredentials(ctx context.Context, cs *ClientSet, credentials extensionsv1alpha1.ClusterCredentials, honourServiceAccountRef bool, scheme *runtime.Scheme) (*ClientSet, error) {
	if credentials.SecretRef != nil {
		return NewClientSetFromSecretRef(ctx, cs, credentials.SecretRef, scheme)
	} else if honourServiceAccountRef && credentials.ServiceAccountRef != nil {
		return NewClientSetFromServiceAccountRef(ctx, cs, credentials.ServiceAccountRef, scheme)
	} else {
		return nil, errors.New("no cluster credentials provided")
	}
}

func NewClientSetFromServiceAccountRef(ctx context.Context, cs *ClientSet, ref *corev1.ObjectReference, scheme *runtime.Scheme) (*ClientSet, error) {
	serviceAccount := &corev1.ServiceAccount{}
	if err := cs.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, serviceAccount); err != nil {
		return nil, err
	}

	childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	secret, err := WaitUntilTokenAvailable(childCtx, cs, serviceAccount)
	if err != nil {
		return nil, err
	}

	return NewClientSetFromSecret(cs.Config, secret, client.Options{
		Scheme: scheme,
	})
}

func NewClientSetFromSecretRef(ctx context.Context, cs *ClientSet, ref *corev1.SecretReference, scheme *runtime.Scheme) (*ClientSet, error) {
	secret := &corev1.Secret{}
	if err := cs.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		return nil, err
	}

	return NewClientSetFromSecret(cs.Config, secret, client.Options{
		Scheme: scheme,
	})
}

// NewClientSetFromSecret creates a new controller ClientSet struct for a given secret.
// Client is created either from "kubeconfig" or "token" and "ca.crt" data keys
func NewClientSetFromSecret(config *rest.Config, secret *corev1.Secret, opts client.Options) (*ClientSet, error) {
	if kubeconfig, ok := secret.Data[KubeConfig]; ok {
		return NewClientSetFromBytes(kubeconfig, opts)
	}

	if token, ok := secret.Data[corev1.ServiceAccountTokenKey]; ok {
		// client from token
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

// KubeConfig is the key for the kubeconfig
const KubeConfig = "kubeconfig"

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
