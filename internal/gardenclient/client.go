/*
SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package gardenclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	authenticationv1alpha1 "github.com/gardener/gardener/pkg/apis/authentication/v1alpha1"
	gardencore "github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencoreclientset "github.com/gardener/gardener/pkg/client/core/clientset/versioned"
	gardenscheme "github.com/gardener/gardener/pkg/client/core/clientset/versioned/scheme"
	"golang.org/x/oauth2/google"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	extensionsv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/utils"
)

const (
	// DataKeyKubeConfig is the key in a secret holding the kubeconfig
	DataKeyKubeConfig = "kubeconfig"
	// DataKeyToken is the key in a secret holding the token
	DataKeyToken = "token"
	// DataKeyServiceaccountJSON is the key in a secret data holding the google service account key.
	DataKeyServiceaccountJSON = "serviceaccount.json"
)

// GetProjectByNamespace returns the project for the given namespace
func GetProjectByNamespace(ctx context.Context, c client.Client, namespace string) (*gardencorev1beta1.Project, error) {
	fieldSelector := client.MatchingFields{gardencore.ProjectNamespace: namespace}
	limit := client.Limit(1)

	projectList := &gardencorev1beta1.ProjectList{}
	if err := c.List(ctx, projectList, fieldSelector, limit); err != nil {
		return nil, fmt.Errorf("failed to fetch project by namespace: %w", err)
	}

	if len(projectList.Items) == 0 {
		return nil, fmt.Errorf("failed to fetch project by namespace: %s", namespace)
	}

	return &projectList.Items[0], nil
}

// RemoveServiceAccountFromProjectMember removes the service account from the members of the project
func RemoveServiceAccountFromProjectMember(ctx context.Context, c client.Client, project *gardencorev1beta1.Project, serviceAccount types.NamespacedName) error {
	isProjectMember, index := IsMember(project.Spec.Members, serviceAccount)
	if !isProjectMember {
		// already removed
		return nil
	}

	// remove member at index
	project.Spec.Members = append(project.Spec.Members[:index], project.Spec.Members[index+1:]...)

	return c.Update(ctx, project)
}

// AddServiceAccountAsProjectMember adds the service account as member to the project with the given roles
func AddServiceAccountAsProjectMember(ctx context.Context, c client.Client, project *gardencorev1beta1.Project, serviceAccount *corev1.ServiceAccount, roles []string) error {
	isProjectMember, _ := IsMember(project.Spec.Members, client.ObjectKeyFromObject(serviceAccount))
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

	if len(roles) > 0 {
		member.Role = roles[0]

		if len(roles) > 1 {
			member.Roles = roles[1:]
		} else {
			member.Roles = nil
		}
	}

	project.Spec.Members = append(project.Spec.Members, member)

	return c.Update(ctx, project)
}

// IsMember returns true together with the index in case the passed service account NamespacedName is contained in the ProjectMember list
func IsMember(members []gardencorev1beta1.ProjectMember, serviceAccount types.NamespacedName) (bool, int) {
	for index, member := range members {
		isServiceAccountKindMember := member.APIGroup == "" && member.Kind == rbacv1.ServiceAccountKind && member.Namespace == serviceAccount.Namespace && member.Name == serviceAccount.Name
		isUserKindMember := member.APIGroup == rbacv1.GroupName && member.Kind == rbacv1.UserKind && member.Name == "system:serviceaccount:"+serviceAccount.Namespace+":"+serviceAccount.Name
		isProjectMember := isServiceAccountKindMember || isUserKindMember

		if isProjectMember {
			return true, index
		}
	}

	return false, -1
}

// ClientSet is a struct containing the configuration for the respective Kubernetes
// cluster, the collection of Kubernetes clients <ClientSet> containing all REST clients
// for the built-in Kubernetes API groups, and the Garden which is a REST clientSet
// for the Garden API group.
type ClientSet struct {
	// contains the configuration for the respective Kubernetes cluster
	*rest.Config

	// default controller-runtime client for the built-in Kubernetes API groups and the Garden API group
	client.Client

	// Kubernetes client containing all REST clients for the built-in Kubernetes API groups
	Kubernetes kubernetes.Interface
}

func NewClientSet(config *rest.Config, client client.Client, kubernetes kubernetes.Interface) *ClientSet {
	return &ClientSet{config, client, kubernetes}
}

func NewClientSetFromClusterCredentials(ctx context.Context, cs *ClientSet, credentials extensionsv1alpha1.ClusterCredentials, honourServiceAccountRef *bool, expirationSeconds *int64, scheme *runtime.Scheme) (*ClientSet, error) {
	if credentials.ShootRef != nil {
		return NewClientSetFromShootRef(ctx, cs, credentials.ShootRef, scheme)
	} else if credentials.SecretRef != nil {
		return NewClientSetFromSecretRef(ctx, cs, credentials.SecretRef, scheme)
	} else if ptr.Deref(honourServiceAccountRef, false) && credentials.ServiceAccountRef != nil {
		return NewClientSetFromServiceAccountRef(ctx, cs, credentials.ServiceAccountRef, expirationSeconds, scheme)
	}

	return nil, errors.New("no cluster credentials provided")
}

func NewClientSetFromServiceAccountRef(ctx context.Context, cs *ClientSet, ref *corev1.ObjectReference, expirationSeconds *int64, scheme *runtime.Scheme) (*ClientSet, error) {
	serviceAccount := &corev1.ServiceAccount{}
	if err := cs.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, serviceAccount); err != nil {
		return nil, err
	}

	token, err := cs.RequestToken(ctx, serviceAccount, expirationSeconds)
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

// NewClientSetFromSecretRef creates a new controller ClientSet struct for a given SecretReference.
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

		if (authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "gcp") ||
			(authInfo.Exec != nil && authInfo.Exec.Command == "gke-gcloud-auth-plugin") {
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

	if err := validateClientConfig(rawConfig); err != nil {
		return nil, err
	}

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	return NewClientSetForConfig(config, opts)
}

// validateClientConfig validates that the auth info of a given kubeconfig doesn't have unsupported fields.
func validateClientConfig(config clientcmdapi.Config) error {
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

func (s *ClientSet) DeleteRoleBinding(ctx context.Context, namespace string, name string) error {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return client.IgnoreNotFound(s.Delete(ctx, roleBinding))
}

func (s *ClientSet) DeleteClusterRoleBinding(ctx context.Context, name string) error {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return client.IgnoreNotFound(s.Delete(ctx, clusterRoleBinding))
}

func (s *ClientSet) DeleteSecret(ctx context.Context, namespace string, name string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return client.IgnoreNotFound(s.Delete(ctx, secret))
}

func (s *ClientSet) DeleteServiceAccount(ctx context.Context, namespace string, name string) error {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return client.IgnoreNotFound(s.Delete(ctx, serviceAccount))
}

func (s *ClientSet) DeletePod(ctx context.Context, namespace string, name string) error {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return client.IgnoreNotFound(s.Delete(ctx, pod))
}

func (s *ClientSet) DeleteRole(ctx context.Context, namespace string, name string) error {
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return client.IgnoreNotFound(s.Delete(ctx, role))
}

func (s *ClientSet) DeleteNamespace(ctx context.Context, namespaceName string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return client.IgnoreNotFound(s.Delete(ctx, ns))
}

func (s *ClientSet) CreateOrUpdateRole(ctx context.Context, namespace string, name string, rules []rbacv1.PolicyRule, labelSet *labels.Set, annotationSet *utils.Set) (*rbacv1.Role, error) {
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return role, CreateOrUpdateDiscardResult(ctx, s, role, func() error {
		role.Labels = labels.Merge(role.Labels, *labelSet)
		role.Annotations = utils.MergeStringMap(role.Annotations, *annotationSet)

		role.Rules = rules

		return nil
	})
}

func (s *ClientSet) CreateOrUpdateNamespace(ctx context.Context, namespaceName string, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}

	return ns, CreateOrUpdateDiscardResult(ctx, s, ns, func() error {
		ns.Labels = labels.Merge(ns.Labels, *labelSet)
		ns.Annotations = utils.MergeStringMap(ns.Annotations, *annotationSet)

		return nil
	})
}

func (s *ClientSet) CreateOrUpdateServiceAccount(ctx context.Context, namespace string, name string, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.ServiceAccount, error) {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return serviceAccount, CreateOrUpdateDiscardResult(ctx, s, serviceAccount, func() error {
		serviceAccount.Labels = labels.Merge(serviceAccount.Labels, *labelSet)
		serviceAccount.Annotations = utils.MergeStringMap(serviceAccount.Annotations, *annotationSet)

		return nil
	})
}

func (s *ClientSet) CreateOrUpdateRoleBinding(ctx context.Context, namespace string, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelSet *labels.Set, annotationSet *utils.Set) (*rbacv1.RoleBinding, error) {
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return roleBinding, CreateOrUpdateDiscardResult(ctx, s, roleBinding, func() error {
		roleBinding.Labels = labels.Merge(roleBinding.Labels, *labelSet)
		roleBinding.Annotations = utils.MergeStringMap(roleBinding.Annotations, *annotationSet)

		roleBinding.Subjects = []rbacv1.Subject{subject}
		roleBinding.RoleRef = roleRef

		return nil
	})
}

// RequestToken requests a token using the TokenRequest API for the given service account
func (s *ClientSet) RequestToken(ctx context.Context, serviceAccount *corev1.ServiceAccount, expirationSeconds *int64) (string, error) {
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: expirationSeconds,
		},
	}

	tokenRequest, err := s.Kubernetes.CoreV1().ServiceAccounts(serviceAccount.Namespace).CreateToken(ctx, serviceAccount.Name, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	return tokenRequest.Status.Token, nil
}

func (s *ClientSet) CreateOrUpdateClusterRoleBinding(ctx context.Context, name string, subject rbacv1.Subject, roleRef rbacv1.RoleRef, labelSet *labels.Set, annotationSet *utils.Set) (*rbacv1.ClusterRoleBinding, error) {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}

	return clusterRoleBinding, CreateOrUpdateDiscardResult(ctx, s, clusterRoleBinding, func() error {
		clusterRoleBinding.Labels = labels.Merge(clusterRoleBinding.Labels, *labelSet)
		clusterRoleBinding.Annotations = utils.MergeStringMap(clusterRoleBinding.Annotations, *annotationSet)

		clusterRoleBinding.Subjects = []rbacv1.Subject{subject}
		clusterRoleBinding.RoleRef = roleRef

		return nil
	})
}

func (s *ClientSet) CreateOrUpdateSecretData(ctx context.Context, namespace string, name string, data map[string][]byte, labelSet *labels.Set, annotationSet *utils.Set) (*corev1.Secret, error) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}

	return secret, CreateOrUpdateDiscardResult(ctx, s, secret, func() error {
		secret.Labels = labels.Merge(secret.Labels, *labelSet)
		secret.Annotations = utils.MergeStringMap(secret.Annotations, *annotationSet)

		secret.Data = data
		secret.Type = corev1.SecretTypeOpaque

		return nil
	})
}

func CreateOrUpdateDiscardResult(ctx context.Context, cs *ClientSet, obj client.Object, f controllerutil.MutateFn) error {
	_, err := ctrl.CreateOrUpdate(ctx, cs.Client, obj, f)
	return err
}
