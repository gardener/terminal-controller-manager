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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-logr/logr"
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
	"regexp"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kErros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Recorder record.EventRecorder
	Log      logr.Logger
}

type ClientSet struct {
	*rest.Config
	client.Client
	Kubernetes kubernetes.Interface
}

func (r *TerminalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha1.Terminal{}).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=dashboard.gardener.cloud,resources=terminals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dashboard.gardener.cloud,resources=terminals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations;mutatingwebhookconfigurations,verbs=list

func (r *TerminalReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	// TODO introduce unique reconcile identifier that is used for logging

	ctx := context.Background()

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

	hostClientSet, hostClientSetErr := NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Host.Credentials)
	targetClientSet, targetClientSetErr := NewClientSetFromClusterCredentials(ctx, gardenClientSet, t.Spec.Target.Credentials)

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
			r.Recorder.Eventf(t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleting, "Deleting external dependencies")
			// our finalizer is present, so lets handle our external dependency

			var errStrings []string
			if deletionErrors := r.deleteExternalDependency(ctx, targetClientSet, hostClientSet, t); deletionErrors != nil {
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				for _, deletionErr := range deletionErrors {
					r.Recorder.Eventf(t, corev1.EventTypeWarning, extensionsv1alpha1.EventDeleteError, deletionErr.Description)
					errStrings = append(errStrings, deletionErr.Description)
				}
				return ctrl.Result{}, errors.New(strings.Join(errStrings, "\n"))
			} else {
				r.Recorder.Eventf(t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleted, "Deleted external dependencies")
			}

			// remove our finalizer from the list and update it.
			finalizers.Delete(extensionsv1alpha1.TerminalName)
			t.Finalizers = finalizers.List()
			if err := r.Update(context.Background(), t); err != nil {
				return ctrl.Result{}, err
			}
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

	err = r.deleteTerminalInCaseWebhookNotConfigured(ctx, gardenClientSet, t)
	if err != nil {
		r.Recorder.Eventf(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, err.Error())
		return ctrl.Result{}, err
	}

	// The object is not being deleted, so if it does not have our finalizer,
	// then lets add the finalizer and update the object.
	finalizers := sets.NewString(t.Finalizers...)
	if !finalizers.Has(extensionsv1alpha1.TerminalName) {
		finalizers.Insert(extensionsv1alpha1.TerminalName)
		t.Finalizers = finalizers.UnsortedList()
		if err := r.Update(context.Background(), t); err != nil {
			return ctrl.Result{}, err
		}
	}

	r.Recorder.Eventf(t, corev1.EventTypeNormal, extensionsv1alpha1.EventReconciling, "Reconciling Terminal state")
	if err := r.reconcileTerminal(ctx, targetClientSet, hostClientSet, t); err != nil {
		r.Recorder.Eventf(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconcileError, err.Description)
		return ctrl.Result{}, errors.New(err.Description)
	}
	r.Recorder.Eventf(t, corev1.EventTypeNormal, extensionsv1alpha1.EventReconciled, "Reconciled Terminal state")

	return ctrl.Result{}, nil
}

func (r *TerminalReconciler) deleteTerminalInCaseWebhookNotConfigured(ctx context.Context, gardenClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	webhookConfigurationOptions := metav1.ListOptions{}
	webhookConfigurationOptions.LabelSelector = labels.SelectorFromSet(map[string]string{
		"terminal": "admission-configuration",
	}).String()

	mutatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().List(webhookConfigurationOptions)
	if err != nil {
		return errors.New(err.Error())
	}
	if len(mutatingWebhookConfigurations.Items) != 1 {
		delete(ctx, gardenClientSet, t)
		return errors.New(fmt.Sprintf("Expected 1 MutatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(mutatingWebhookConfigurations.Items)))
	}
	mutatingWebhookConfiguration := mutatingWebhookConfigurations.Items[0]
	if mutatingWebhookConfiguration.ObjectMeta.CreationTimestamp.After(t.ObjectMeta.CreationTimestamp.Time) {
		delete(ctx, gardenClientSet, t)
		return errors.New(fmt.Sprintf("Terminal %s has been created before mutating webhook was configured. Deleting resource", t.ObjectMeta.Name))
	}

	validatingWebhookConfigurations, err := gardenClientSet.Kubernetes.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().List(webhookConfigurationOptions)
	if err != nil {
		return errors.New(err.Error())
	}
	if len(validatingWebhookConfigurations.Items) != 1 {
		delete(ctx, gardenClientSet, t)
		return errors.New(fmt.Sprintf("Expected 1 ValidatingWebhookConfiguration for terminals but found %d with label 'terminal=admission-configuration'. Deleting terminal resource", len(validatingWebhookConfigurations.Items)))
	}
	validatingWebhookConfiguration := validatingWebhookConfigurations.Items[0]
	if validatingWebhookConfiguration.ObjectMeta.CreationTimestamp.After(t.ObjectMeta.CreationTimestamp.Time) {
		delete(ctx, gardenClientSet, t)
		return errors.New(fmt.Sprintf("Terminal %s has been created before validating webhook was configured. Deleting resource", t.ObjectMeta.Name))
	}
	return nil
}

// deleteExternalDependency deletes external dependencies on target and host cluster. In case of an error on the target cluster (e.g. api server cannot be reached) the dependencies on the host cluster are still tried to delete.
func (r *TerminalReconciler) deleteExternalDependency(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) []*extensionsv1alpha1.LastError {
	var lastErrors []*extensionsv1alpha1.LastError

	if targetErr := r.deleteTargetClusterDepencies(ctx, targetClientSet, t); targetErr != nil {
		lastErrors = append(lastErrors, targetErr)
	}
	if hostErr := r.deleteHostClusterDepencies(ctx, hostClientSet, t); hostErr != nil {
		lastErrors = append(lastErrors, hostErr)
	}

	if len(lastErrors) >= 0 {
		return lastErrors
	}

	return nil
}

func (r *TerminalReconciler) deleteTargetClusterDepencies(ctx context.Context, targetClientSet *ClientSet, t *extensionsv1alpha1.Terminal) *extensionsv1alpha1.LastError {
	if targetClientSet != nil {
		if err := deleteAccessToken(ctx, targetClientSet, t); err != nil {
			return formatError("Failed to delete access token", err)
		}
	} else {
		r.Recorder.Eventf(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in target cluster for terminal identifier: %s", t.Spec.Identifier)
	}
	return nil
}

func (r *TerminalReconciler) deleteHostClusterDepencies(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) *extensionsv1alpha1.LastError {
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
		r.Recorder.Eventf(t, corev1.EventTypeWarning, extensionsv1alpha1.EventReconciling, "Could not clean up resources in host cluster for terminal identifier: %s", t.Spec.Identifier)
	}
	return nil
}

func deleteAccessToken(ctx context.Context, targetClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	var err error

	bindingName := extensionsv1alpha1.TerminalAccessResourceNamePrefix + t.Spec.Identifier
	switch t.Spec.Target.BindingKind {
	case extensionsv1alpha1.BindingKindClusterRoleBinding:
		err = deleteClusterRoleBinding(ctx, targetClientSet, bindingName)
	case extensionsv1alpha1.BindingKindRoleBinding:
		err = deleteRoleBinding(ctx, targetClientSet, *t.Spec.Target.Namespace, bindingName)
	default:
		panic("unknown BindingKind")
	}
	if err != nil {
		return err
	}

	if err := deleteServiceAccount(ctx, targetClientSet, *t.Spec.Target.Namespace, extensionsv1alpha1.TerminalAccessResourceNamePrefix+t.Spec.Identifier); err != nil {
		return err
	}

	if t.Spec.Target.TemporaryNamespace {
		if err := deleteNamespace(ctx, targetClientSet, *t.Spec.Target.Namespace); err != nil {
			return err
		}
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

func (r *TerminalReconciler) reconcileTerminal(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) *extensionsv1alpha1.LastError {
	labelsSet, err := t.NewLabelsSet()
	if err != nil {
		return formatError("Failed to reconcile terminal", err)
	}

	if err = r.createOrUpdateAttachPodSecret(ctx, hostClientSet, t, labelsSet); err != nil {
		return formatError("Failed to create or update resources needed for attaching to a pod", err)
	}

	kubeconfigSecret, err := createOrUpdateAdminKubeconfig(ctx, targetClientSet, hostClientSet, t, labelsSet)
	if err != nil {
		return formatError("Failed to create or update admin kubeconfig", err)
	}

	if _, err = r.createOrUpdateTerminalPod(ctx, hostClientSet, t, kubeconfigSecret.Name, labelsSet); err != nil {
		return formatError("Failed to create or update terminal pod", err)
	}

	return nil
}

func (r *TerminalReconciler) createOrUpdateAttachPodSecret(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelsSet *labels.Set) error {
	if t.Spec.Host.TemporaryNamespace {
		if _, err := createOrUpdateNamespace(ctx, hostClientSet, *t.Spec.Host.Namespace, labelsSet); err != nil {
			return err
		}
	}

	attachPodServiceAccount, err := createOrUpdateServiceAccount(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, labelsSet)
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
	_, err = createOrUpdateRoleBinding(ctx, hostClientSet, *t.Spec.Host.Namespace, extensionsv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier, subject, roleRef, labelsSet)
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

	return delete(ctx, cs, role)
}

func createOrUpdateNamespace(ctx context.Context, cs *ClientSet, namespaceName string, labelsSet *labels.Set) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return ns, CreateOrUpdateDiscardResult(ctx, cs, ns, func() error {
		ns.Labels = labels.Merge(ns.Labels, *labelsSet)
		return nil
	})
}

func deleteNamespace(ctx context.Context, cs *ClientSet, namespaceName string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return delete(ctx, cs, ns)
}

func createOrUpdateServiceAccount(ctx context.Context, cs *ClientSet, namespace string, name string, labelsSet *labels.Set) (*corev1.ServiceAccount, error) {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return serviceAccount, CreateOrUpdateDiscardResult(ctx, cs, serviceAccount, func() error {
		serviceAccount.Labels = labels.Merge(serviceAccount.Labels, *labelsSet)
		return nil
	})
}

func deleteServiceAccount(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return delete(ctx, cs, serviceAccount)
}

func createOrUpdateRoleBinding(ctx context.Context, cs *ClientSet, namespace string, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelsSet *labels.Set) (*rbacv1.RoleBinding, error) {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return roleBinding, CreateOrUpdateDiscardResult(ctx, cs, roleBinding, func() error {
		roleBinding.Labels = labels.Merge(roleBinding.Labels, *labelsSet)

		roleBinding.Subjects = []rbacv1.Subject{subject}
		roleBinding.RoleRef = roleRef

		return nil
	})
}

func deleteRoleBinding(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return delete(ctx, cs, roleBinding)
}

func createOrUpdateClusterRoleBinding(ctx context.Context, cs *ClientSet, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelsSet *labels.Set) (*rbacv1.ClusterRoleBinding, error) {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return clusterRoleBinding, CreateOrUpdateDiscardResult(ctx, cs, clusterRoleBinding, func() error {
		clusterRoleBinding.Labels = labels.Merge(clusterRoleBinding.Labels, *labelsSet)

		clusterRoleBinding.Subjects = []rbacv1.Subject{subject}
		clusterRoleBinding.RoleRef = roleRef

		return nil
	})
}

func deleteClusterRoleBinding(ctx context.Context, cs *ClientSet, name string) error {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return delete(ctx, cs, clusterRoleBinding)
}

func createOrUpdateAdminKubeconfig(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelsSet *labels.Set) (*corev1.Secret, error) {
	accessSecret, err := createAccessToken(ctx, targetClientSet, t, labelsSet)
	if err != nil {
		return nil, err
	}

	return createOrUpdateKubeconfig(ctx, targetClientSet, hostClientSet, t, accessSecret, labelsSet)
}

func createAccessToken(ctx context.Context, targetClientSet *ClientSet, t *extensionsv1alpha1.Terminal, labelsSet *labels.Set) (*corev1.Secret, error) {
	if t.Spec.Target.TemporaryNamespace {
		if _, err := createOrUpdateNamespace(ctx, targetClientSet, *t.Spec.Target.Namespace, labelsSet); err != nil {
			return nil, err
		}
	}

	accessServiceAccount, err := createOrUpdateServiceAccount(ctx, targetClientSet, *t.Spec.Target.Namespace, extensionsv1alpha1.TerminalAccessResourceNamePrefix+t.Spec.Identifier, labelsSet)
	if err != nil {
		return nil, err
	}

	subject := rbacv1.Subject{
		Kind:      rbacv1.ServiceAccountKind,
		Namespace: accessServiceAccount.Namespace,
		Name:      accessServiceAccount.Name,
	}
	roleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     t.Spec.Target.RoleName,
	}
	bindingName := extensionsv1alpha1.TerminalAccessResourceNamePrefix + t.Spec.Identifier

	switch t.Spec.Target.BindingKind {
	case extensionsv1alpha1.BindingKindClusterRoleBinding:
		_, err = createOrUpdateClusterRoleBinding(ctx, targetClientSet, bindingName, subject, roleRef, labelsSet)
	case extensionsv1alpha1.BindingKindRoleBinding:
		_, err = createOrUpdateRoleBinding(ctx, targetClientSet, *t.Spec.Target.Namespace, bindingName, subject, roleRef, labelsSet)
	default:
		panic("unknown BindingKind")
	}
	if err != nil {
		return nil, err
	}

	childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return WaitUntilTokenAvailable(childCtx, targetClientSet, accessServiceAccount)
}

// WaitUntilTokenAvailable waits until the secret that is referenced .
func WaitUntilTokenAvailable(ctx context.Context, cs *ClientSet, serviceAccount *corev1.ServiceAccount) (*corev1.Secret, error) {

	fieldSelector := fields.SelectorFromSet(map[string]string{
		"metadata.name": serviceAccount.Name,
	}).String()

	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return cs.Kubernetes.CoreV1().ServiceAccounts(serviceAccount.Namespace).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return cs.Kubernetes.CoreV1().ServiceAccounts(serviceAccount.Namespace).Watch(options)
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

func createOrUpdateKubeconfig(ctx context.Context, targetClientSet *ClientSet, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal, accessSecret *corev1.Secret, labelsSet *labels.Set) (*corev1.Secret, error) {
	clusterName, err := clusterNameForCredential(t.Spec.Target.Credentials)
	if err != nil {
		return nil, err
	}
	contextNamespace := t.Spec.Target.KubeconfigContextNamespace
	apiServerHost := targetClientSet.Host
	kubeconfig, err := GenerateKubeconfigFromTokenSecret(clusterName, contextNamespace, apiServerHost, accessSecret, labelsSet)
	if err != nil {
		return nil, err
	}

	kubeconfigSecretName := extensionsv1alpha1.KubeconfigSecretResourceNamePrefix + t.Spec.Identifier

	data := map[string][]byte{
		"kubeconfig": kubeconfig,
	}

	return createOrUpdateSecretData(ctx, hostClientSet, *t.Spec.Host.Namespace, kubeconfigSecretName, data, labelsSet)
}

func deleteKubeconfig(ctx context.Context, hostClientSet *ClientSet, t *extensionsv1alpha1.Terminal) error {
	kubeconfigSecretName := extensionsv1alpha1.KubeconfigSecretResourceNamePrefix + t.Spec.Identifier
	return deleteSecret(ctx, hostClientSet, *t.Spec.Host.Namespace, kubeconfigSecretName)
}

func createOrUpdateSecretData(ctx context.Context, cs *ClientSet, namespace string, name string, data map[string][]byte, labelsSet *labels.Set) (*corev1.Secret, error) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return secret, CreateOrUpdateDiscardResult(ctx, cs, secret, func() error {
		secret.Labels = labels.Merge(secret.Labels, *labelsSet)

		secret.Data = data
		secret.Type = corev1.SecretTypeOpaque

		return nil
	})
}

func deleteSecret(ctx context.Context, cs *ClientSet, namespace string, name string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return delete(ctx, cs, secret)
}

// GenerateKubeconfigFromTokenSecret generates a kubeconfig using the provided
func GenerateKubeconfigFromTokenSecret(clusterName string, contextNamespace string, apiServerHost string, secret *corev1.Secret, labelsSet *labels.Set) ([]byte, error) {
	if apiServerHost == "" {
		return nil, errors.New("api server host is required")
	}

	matched, _ := regexp.MatchString(`^https:\/\/localhost:\d{1,5}$`, apiServerHost)
	if matched {
		apiServerHost = "https://kubernetes.default.svc.cluster.local"
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
					Server:                   apiServerHost,
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

func (r *TerminalReconciler) createOrUpdateTerminalPod(ctx context.Context, cs *ClientSet, t *extensionsv1alpha1.Terminal, kubeconfigSecretName string, labelsSet *labels.Set) (*corev1.Pod, error) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: *t.Spec.Host.Namespace, Name: extensionsv1alpha1.TerminalPodResourceNamePrefix + t.Spec.Identifier}}

	t.Status.PodName = pod.Name
	err := r.Status().Update(ctx, t)
	if err != nil {
		return nil, err
	}

	return pod, CreateOrUpdateDiscardResult(ctx, cs, pod, func() error {
		pod.Labels = labels.Merge(pod.Labels, t.Spec.Host.Pod.Labels)
		pod.Labels = labels.Merge(pod.Labels, *labelsSet)

		volumeExists := func(name string) bool {
			for _, volume := range pod.Spec.Volumes {
				if volume.Name == name {
					return true
				}
			}
			return false
		}
		tolerationExists := func(key string) bool {
			for _, toleration := range pod.Spec.Tolerations {
				if toleration.Key == key {
					return true
				}
			}
			return false
		}

		containerName := "terminal"
		if len(pod.Spec.Containers) == 0 {
			container := corev1.Container{Name: containerName}

			container.VolumeMounts = []corev1.VolumeMount{
				{
					Name:      "kubeconfig",
					MountPath: "mnt/.kube",
				},
			}
			container.Env = []corev1.EnvVar{
				{
					Name:  "KUBECONFIG",
					Value: "/mnt/.kube/config",
				},
			}
			if t.Spec.Host.Pod.Privileged {
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
		}
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

		pod.Spec.Containers[containerIndex].Image = t.Spec.Host.Pod.ContainerImage
		pod.Spec.Containers[containerIndex].Stdin = true
		pod.Spec.Containers[containerIndex].TTY = true
		if pod.Spec.Containers[containerIndex].SecurityContext == nil {
			pod.Spec.Containers[containerIndex].SecurityContext = &corev1.SecurityContext{}
		}
		pod.Spec.Containers[containerIndex].SecurityContext.Privileged = &t.Spec.Host.Pod.Privileged

		pod.Spec.NodeSelector = t.Spec.Host.Pod.NodeSelector

		if len(pod.Spec.Volumes) == 0 {
			pod.Spec.Volumes = []corev1.Volume{}
		}
		if !volumeExists("kubeconfig") {
			pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
				Name: "kubeconfig",
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
			})
		}

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

	return delete(ctx, cs, pod)
}

func delete(ctx context.Context, cs *ClientSet, obj runtime.Object) error {
	err := cs.Delete(ctx, obj)
	if kErros.IsNotFound(err) {
		return nil
	}
	return err
}

func NewClientSet(config *rest.Config, client client.Client, kubernetes kubernetes.Interface) *ClientSet {
	return &ClientSet{config, client, kubernetes}
}

func NewClientSetFromClusterCredentials(ctx context.Context, cs *ClientSet, credentials extensionsv1alpha1.ClusterCredentials) (*ClientSet, error) {
	if credentials.SecretRef != nil {
		return NewClientSetFromSecretRef(ctx, cs, credentials.SecretRef)
	} else if credentials.ServiceAccountRef != nil {
		return NewClientSetFromServiceAccountRef(ctx, cs, credentials.ServiceAccountRef)
	} else {
		return nil, errors.New("no cluster credentials provided")
	}
}

func NewClientSetFromServiceAccountRef(ctx context.Context, cs *ClientSet, ref *corev1.ObjectReference) (*ClientSet, error) {
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

	return NewClientSetFromSecret(cs.Config, secret, client.Options{})
}

func NewClientSetFromSecretRef(ctx context.Context, cs *ClientSet, ref *corev1.SecretReference) (*ClientSet, error) {
	secret := &corev1.Secret{}
	if err := cs.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		return nil, err
	}

	return NewClientSetFromSecret(cs.Config, secret, client.Options{})
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

func CreateOrUpdateDiscardResult(ctx context.Context, cs *ClientSet, obj runtime.Object, f controllerutil.MutateFn) error {
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

// FormatLastErrDescription formats the error message string for the last occurred error.
func FormatLastErrDescription(err error) string {
	errString := err.Error()
	if len(errString) > 0 {
		errString = strings.ToUpper(string(errString[0])) + errString[1:]
	}
	return errString
}

// EncodeBase64 takes a byte slice and returns the Base64-encoded string.
func EncodeBase64(in []byte) string {
	encodedLength := base64.StdEncoding.EncodedLen(len(in))
	buffer := make([]byte, encodedLength)
	out := buffer[0:encodedLength]
	base64.StdEncoding.Encode(out, in)
	return string(out)
}

// RenderLocalTemplate uses a template <tpl> given as a string and renders it. Thus, the template does not
// necessarily need to be stored as a file.
func RenderLocalTemplate(tpl string, values interface{}) ([]byte, error) {
	templateObj, err := template.
		New("tpl").
		Parse(tpl)
	if err != nil {
		return nil, err
	}
	return render(templateObj, values)
}

// render takes a text/template.Template object <temp> and an interface of <values> which are used to render the
// template. It returns the rendered result as byte slice, or an error if something went wrong.
func render(tpl *template.Template, values interface{}) ([]byte, error) {
	var result bytes.Buffer
	err := tpl.Execute(&result, values)
	if err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

// KubeConfig is the key for the kubeconfig
const KubeConfig = "kubeconfig"

// NewClientSetFromBytes creates a new controller ClientSet struct for a given kubeconfig byte slice.
func NewClientSetFromBytes(kubeconfig []byte, opts client.Options) (*ClientSet, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
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
