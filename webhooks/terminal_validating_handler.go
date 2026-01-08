/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package webhooks

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/api/validation/path"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/sets"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
)

// Supported roles for project members, based on Gardener's core types
var supportedRoles = sets.New(
	"owner",
	"admin",
	"viewer",
	"uam", // user access manager
	"serviceaccountmanager",
)

const (
	extensionRoleMaxLength = 20
	extensionRolePrefix    = "extension:"
)

// TerminalValidator handles Terminal
type TerminalValidator struct {
	Client      client.Client
	Log         logr.Logger
	Config      *v1alpha1.ControllerManagerConfiguration
	configMutex sync.RWMutex

	// Decoder decodes objects
	Decoder admission.Decoder
}

func (h *TerminalValidator) getConfig() *v1alpha1.ControllerManagerConfiguration {
	h.configMutex.RLock()
	defer h.configMutex.RUnlock()

	return h.Config
}

// Mainly used for tests to inject config
func (h *TerminalValidator) injectConfig(config *v1alpha1.ControllerManagerConfiguration) {
	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	h.Config = config
}

func (h *TerminalValidator) validatingTerminalFn(ctx context.Context, t *v1alpha1.Terminal, oldT *v1alpha1.Terminal, admissionReq admissionv1.AdmissionRequest) (bool, string, error) {
	userInfo := admissionReq.UserInfo

	if admissionReq.Operation != admissionv1.Create {
		specFldPath := field.NewPath("spec")
		if err := validateImmutableField(t.Spec, oldT.Spec, specFldPath); err != nil {
			return false, err.Error(), nil
		}

		createdByFldPath := field.NewPath("metadata", "annotations", v1alpha1.GardenCreatedBy)
		if err := validateImmutableField(t.Annotations[v1alpha1.GardenCreatedBy], oldT.Annotations[v1alpha1.GardenCreatedBy], createdByFldPath); err != nil {
			return false, err.Error(), nil
		}

		// only same user is allowed to keep terminal session alive
		userFromAnnotations := t.Annotations[v1alpha1.GardenCreatedBy]
		changedBySameUser := userFromAnnotations == admissionReq.UserInfo.Username

		if t.Annotations[v1alpha1.TerminalLastHeartbeat] != oldT.Annotations[v1alpha1.TerminalLastHeartbeat] && !changedBySameUser {
			return false, field.Forbidden(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), userInfo.Username+" is not allowed to change this field").Error(), nil
		}
	}

	lastHeartbeat := t.Annotations[v1alpha1.TerminalLastHeartbeat]
	if len(lastHeartbeat) > 0 {
		lastHeartBeatParsed, err := time.Parse(time.RFC3339, lastHeartbeat)
		if err != nil {
			return false, field.Invalid(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), lastHeartbeat, "failed to parse time").Error(), nil
		}

		if lastHeartBeatParsed.After(time.Now().UTC()) {
			return false, field.Forbidden(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), "time must not be in the future").Error(), nil
		}
	}

	fldPath := field.NewPath("spec", "target", "namespace")
	if err := validateRequiredField(t.Spec.Target.Namespace, fldPath); err != nil {
		return false, err.Error(), nil
	}

	if err := validateDNS1123Subdomain(*t.Spec.Target.Namespace, fldPath); err != nil {
		return false, err.Error(), nil
	}

	fldPath = field.NewPath("spec", "host", "namespace")
	if err := validateRequiredField(t.Spec.Host.Namespace, fldPath); err != nil {
		return false, err.Error(), nil
	}

	if err := validateDNS1123Subdomain(*t.Spec.Host.Namespace, fldPath); err != nil {
		return false, err.Error(), nil
	}

	fldPath = field.NewPath("spec", "target", "kubeconfigContextNamespace")
	if err := validateRequiredField(&t.Spec.Target.KubeconfigContextNamespace, fldPath); err != nil {
		return false, err.Error(), nil
	}

	if err := validateDNS1123Subdomain(t.Spec.Target.KubeconfigContextNamespace, fldPath); err != nil {
		return false, err.Error(), nil
	}

	if err := validatePodFields(t); err != nil {
		return false, err.Error(), nil
	}

	if err := h.validateCredentials(t); err != nil {
		return false, err.Error(), nil
	}

	if err := h.validateTargetAuthorization(t); err != nil {
		return false, err.Error(), nil
	}

	if err := validateAPIServerFields(t); err != nil {
		return false, err.Error(), nil
	}

	if allowed, err := h.canGetCredential(ctx, userInfo, t.Spec.Target.Credentials); err != nil {
		return false, err.Error(), nil
	} else if !allowed {
		return false, field.Forbidden(field.NewPath("spec", "target", "credentials"), userInfo.Username+" is not allowed to read target credential").Error(), nil
	}

	if allowed, err := h.canGetCredential(ctx, userInfo, t.Spec.Host.Credentials); err != nil {
		return false, err.Error(), nil
	} else if !allowed {
		return false, field.Forbidden(field.NewPath("spec", "host", "credentials"), userInfo.Username+" is not allowed to read host credential").Error(), nil
	}

	if ptr.Deref(t.Spec.Target.CleanupProjectMembership, false) {
		if !ptr.Deref(h.getConfig().HonourCleanupProjectMembership, false) {
			return false, field.Forbidden(field.NewPath("spec", "target", "cleanupProjectMembership"), "field is forbidden by configuration").Error(), nil
		}

		if t.Spec.Target.Credentials.ServiceAccountRef == nil {
			return false, field.Required(field.NewPath("spec", "target", "credentials", "serviceAccountRef"), "field is required").Error(), nil
		}

		if t.Spec.Target.Credentials.ServiceAccountRef.Namespace != t.Namespace {
			return false, field.Invalid(field.NewPath("spec", "target", "credentials", "serviceAccountRef", "namespace"), t.Spec.Target.Credentials.ServiceAccountRef.Namespace, "only allowed to reference serviceaccount within the same namespace when cleanupProjectMembership is enabled").Error(), nil
		}

		if allowed, err := h.canManageProjectMembers(ctx, userInfo, t.Namespace); err != nil {
			return false, err.Error(), nil
		} else if !allowed {
			return false, field.Forbidden(field.NewPath("spec", "target", "cleanupProjectMembership"), userInfo.Username+" is not allowed to manage project members").Error(), nil
		}
	}

	return true, "allowed to be admitted", nil
}

func validateRequiredField(val *string, fldPath *field.Path) error {
	if val == nil || len(*val) == 0 {
		return field.Required(fldPath, "field is required")
	}

	return nil
}

func validateDNS1123Subdomain(value string, fldPath *field.Path) error {
	if errs := utilvalidation.IsDNS1123Subdomain(value); len(errs) > 0 {
		return field.Invalid(fldPath, value, strings.Join(errs, ", "))
	}

	return nil
}

func validateDNSSubdomain(value string, fldPath *field.Path) error {
	if errs := validation.NameIsDNSSubdomain(value, false); len(errs) > 0 {
		return field.Invalid(fldPath, value, strings.Join(errs, ", "))
	}

	return nil
}

func validateDNSLabel(value string, fldPath *field.Path) error {
	if errs := validation.NameIsDNSLabel(value, false); len(errs) > 0 {
		return field.Invalid(fldPath, value, strings.Join(errs, ", "))
	}

	return nil
}

func validateDNS1035Label(value string, fldPath *field.Path) error {
	if errs := utilvalidation.IsDNS1035Label(value); len(errs) > 0 {
		return field.Invalid(fldPath, value, strings.Join(errs, ", "))
	}

	return nil
}

// ValidateRBACName is exported to allow types outside of the RBAC API group to reuse this validation logic
// Minimal validation of names for roles and bindings. Identical to the validation for Openshift. See:
// * https://github.com/kubernetes/kubernetes/blob/60db507b279ce45bd16ea3db49bf181f2aeb3c3d/pkg/api/validation/name.go
// * https://github.com/openshift/origin/blob/388478c40e751c4295dcb9a44dd69e5ac65d0e3b/pkg/api/helpers.go
// Source: https://github.com/kubernetes/kubernetes/blob/df11db1c0f08fab3c0baee1e5ce6efbf816af7f1/pkg/apis/rbac/validation/validation.go#L28C1-L34C2
func ValidateRBACName(name string) []string {
	return path.IsValidPathSegmentName(name)
}

func validateRBACName(value string, fldPath *field.Path) error {
	if errs := ValidateRBACName(value); len(errs) > 0 {
		return field.Invalid(fldPath, value, strings.Join(errs, ", "))
	}

	return nil
}

// validateRoleRefForBindingKind validates RoleRef based on BindingKind restrictions:
// - For RoleBinding: can reference a Role in the same namespace or a ClusterRole
// - For ClusterRoleBinding: can only reference a ClusterRole
func validateRoleRefForBindingKind(roleRef rbacv1.RoleRef, bindingKind v1alpha1.BindingKind, fldPath *field.Path) error {
	switch bindingKind {
	case v1alpha1.BindingKindClusterRoleBinding:
		if roleRef.Kind != "ClusterRole" {
			return field.Invalid(fldPath.Child("kind"), roleRef.Kind, "ClusterRoleBinding can only reference a ClusterRole")
		}
	case v1alpha1.BindingKindRoleBinding:
		if roleRef.Kind != "Role" && roleRef.Kind != "ClusterRole" {
			return field.Invalid(fldPath.Child("kind"), roleRef.Kind, "RoleBinding can only reference a Role or ClusterRole")
		}
	default:
		return field.Invalid(field.NewPath("bindingKind"), bindingKind, "must be 'RoleBinding' or 'ClusterRoleBinding'")
	}

	return nil
}

// validateLabels validates that the provided labels map contains valid Kubernetes label keys and values
func validateLabels(labels map[string]string, fldPath *field.Path) error {
	if errs := metav1validation.ValidateLabels(labels, fldPath); len(errs) > 0 {
		return errs.ToAggregate()
	}

	return nil
}

func validateImmutableField(newVal, oldVal interface{}, fldPath *field.Path) error {
	if !equality.Semantic.DeepEqual(oldVal, newVal) {
		return field.Invalid(fldPath, newVal, validation.FieldImmutableErrorMsg)
	}

	return nil
}

func validatePodFields(t *v1alpha1.Terminal) error {
	if len(t.Spec.Host.Pod.ContainerImage) == 0 {
		if err := validateRequiredContainerFields(t.Spec.Host.Pod.Container, field.NewPath("spec", "host", "pod", "container")); err != nil {
			return err
		}
	}

	if err := validateLabels(t.Spec.Host.Pod.Labels, field.NewPath("spec", "host", "pod", "labels")); err != nil {
		return err
	}

	if err := validateLabels(t.Spec.Host.Pod.NodeSelector, field.NewPath("spec", "host", "pod", "nodeSelector")); err != nil {
		return err
	}

	return nil
}

func validateRequiredContainerFields(container *v1alpha1.Container, fldPath *field.Path) error {
	if container == nil {
		return field.Required(fldPath, "field is required")
	}

	return validateRequiredField(&container.Image, fldPath.Child("image"))
}

// ValidateCAData validates that caData is either empty or a PEM bundle consisting
// of one or more "CERTIFICATE" blocks, each parseable as an X.509 certificate,
// with no trailing non-PEM data.
func ValidateCAData(caData []byte) error {
	if len(caData) == 0 {
		return nil // optional
	}

	rest := caData
	parsedAny := false

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected PEM block type %q (expected CERTIFICATE)", block.Type)
		}

		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("cannot parse X.509 certificate: %w", err)
		}

		parsedAny = true
	}

	if !parsedAny {
		return errors.New("CA bundle must contain at least one PEM-encoded certificate")
	}

	if len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("CA bundle contains trailing non-PEM data")
	}

	return nil
}

// validateURL validates that the provided string is a valid URL with https scheme.
func validateURL(value string, fldPath *field.Path) error {
	if value == "" {
		return nil // optional
	}

	u, err := url.Parse(value)
	if err != nil {
		return field.Invalid(fldPath, value, fmt.Sprintf("must be a valid URL: %v", err))
	}

	if u.Scheme != "https" {
		return field.Invalid(fldPath, value, "URL scheme must be https")
	}

	if u.Host == "" {
		return field.Invalid(fldPath, value, "URL must have a host")
	}

	return nil
}

func validateAPIServerFields(t *v1alpha1.Terminal) error {
	if t.Spec.Target.APIServerServiceRef != nil {
		if err := validateRequiredField(&t.Spec.Target.APIServerServiceRef.Name, field.NewPath("spec", "target", "apiServerServiceRef", "name")); err != nil {
			return err
		}

		if err := validateDNS1035Label(t.Spec.Target.APIServerServiceRef.Name, field.NewPath("spec", "target", "apiServerServiceRef", "name")); err != nil {
			return err
		}

		if t.Spec.Target.APIServerServiceRef.Namespace != "" {
			if err := validateDNS1123Subdomain(t.Spec.Target.APIServerServiceRef.Namespace, field.NewPath("spec", "target", "apiServerServiceRef", "namespace")); err != nil {
				return err
			}
		}
	}

	if t.Spec.Target.APIServer != nil {
		if t.Spec.Target.APIServer.ServiceRef != nil {
			if err := validateRequiredField(&t.Spec.Target.APIServer.ServiceRef.Name, field.NewPath("spec", "target", "apiServer", "serviceRef", "name")); err != nil {
				return err
			}

			if err := validateDNS1035Label(t.Spec.Target.APIServer.ServiceRef.Name, field.NewPath("spec", "target", "apiServer", "serviceRef", "name")); err != nil {
				return err
			}

			if t.Spec.Target.APIServer.ServiceRef.Namespace != "" {
				if err := validateDNS1123Subdomain(t.Spec.Target.APIServer.ServiceRef.Namespace, field.NewPath("spec", "target", "apiServer", "serviceRef", "namespace")); err != nil {
					return err
				}
			}
		}

		if err := validateURL(t.Spec.Target.APIServer.Server, field.NewPath("spec", "target", "apiServer", "server")); err != nil {
			return err
		}

		if err := ValidateCAData(t.Spec.Target.APIServer.CAData); err != nil {
			return field.Invalid(field.NewPath("spec", "target", "apiServer", "caData"), "<redacted>", err.Error())
		}
	}

	return nil
}

func toAuthZExtraValue(authNVal map[string]authenticationv1.ExtraValue) map[string]authorizationv1.ExtraValue {
	authZVal := make(map[string]authorizationv1.ExtraValue)
	for k, v := range authNVal {
		authZVal[k] = authorizationv1.ExtraValue(v)
	}

	return authZVal
}

func (h *TerminalValidator) validateCredentials(t *v1alpha1.Terminal) error {
	if err := validateCredential(t.Spec.Target.Credentials, field.NewPath("spec", "target", "credentials"), h.getConfig().HonourServiceAccountRefTargetCluster); err != nil {
		return err
	}

	return validateCredential(t.Spec.Host.Credentials, field.NewPath("spec", "host", "credentials"), h.getConfig().HonourServiceAccountRefHostCluster)
}

func validateCredential(cred v1alpha1.ClusterCredentials, fldPath *field.Path, honourServiceAccountRef *bool) error {
	if cred.ShootRef != nil && cred.ServiceAccountRef != nil {
		return field.Forbidden(fldPath, "only one of 'shootRef' or 'serviceAccountRef' must be set")
	}

	if !ptr.Deref(honourServiceAccountRef, false) {
		if cred.ServiceAccountRef != nil {
			return field.Forbidden(fldPath.Child("serviceAccountRef"), "field is forbidden by configuration")
		}

		if cred.ShootRef == nil {
			return field.Required(fldPath.Child("shootRef"), "field is required")
		}
	} else {
		if cred.ShootRef == nil && cred.ServiceAccountRef == nil {
			return field.Required(fldPath, "field requires either ShootRef or ServiceAccountRef to be set")
		}
	}

	if cred.ShootRef != nil {
		if err := validateRequiredField(&cred.ShootRef.Name, fldPath.Child("shootRef", "name")); err != nil {
			return err
		}

		if err := validateDNSLabel(cred.ShootRef.Name, fldPath.Child("shootRef", "name")); err != nil {
			return err
		}

		if err := validateRequiredField(&cred.ShootRef.Namespace, fldPath.Child("shootRef", "namespace")); err != nil {
			return err
		}

		if err := validateDNS1123Subdomain(cred.ShootRef.Namespace, fldPath.Child("shootRef", "namespace")); err != nil {
			return err
		}
	}

	if cred.ServiceAccountRef != nil {
		if err := validateRequiredField(&cred.ServiceAccountRef.Name, fldPath.Child("serviceAccountRef", "name")); err != nil {
			return err
		}

		if err := validateDNSSubdomain(cred.ServiceAccountRef.Name, fldPath.Child("serviceAccountRef", "name")); err != nil {
			return err
		}

		if err := validateRequiredField(&cred.ServiceAccountRef.Namespace, fldPath.Child("serviceAccountRef", "namespace")); err != nil {
			return err
		}

		if err := validateDNS1123Subdomain(cred.ServiceAccountRef.Namespace, fldPath.Child("serviceAccountRef", "namespace")); err != nil {
			return err
		}
	}

	return nil
}

func (h *TerminalValidator) validateTargetAuthorization(t *v1alpha1.Terminal) error {
	fldPath := field.NewPath("spec", "target")

	if t.Spec.Target.RoleName != "" {
		if err := validateRBACName(t.Spec.Target.RoleName, fldPath.Child("roleName")); err != nil {
			return err
		}

		if t.Spec.Target.BindingKind != v1alpha1.BindingKindClusterRoleBinding && t.Spec.Target.BindingKind != v1alpha1.BindingKindRoleBinding {
			return field.Invalid(fldPath.Child("bindingKind"), t.Spec.Target.BindingKind, "field should be either "+v1alpha1.BindingKindClusterRoleBinding.String()+" or "+v1alpha1.BindingKindRoleBinding.String())
		}
	}

	if t.Spec.Target.Authorization != nil {
		fldPath = fldPath.Child("authorization")

		if err := validateRoleBindings(t, fldPath); err != nil {
			return err
		}

		if err := h.validateProjectMemberships(t, fldPath); err != nil {
			return err
		}
	}

	return nil
}

func validateRoleBindings(t *v1alpha1.Terminal, fldPath *field.Path) error {
	fldPath = fldPath.Child("roleBindings")

	for index, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
		if err := validateRequiredField(&roleBinding.RoleRef.Name, fldPath.Index(index).Child("roleRef", "name")); err != nil {
			return err
		}

		if err := validateRBACName(roleBinding.RoleRef.Name, fldPath.Index(index).Child("roleRef", "name")); err != nil {
			return err
		}

		if roleBinding.RoleRef.APIGroup != "rbac.authorization.k8s.io" {
			return field.Invalid(fldPath.Index(index).Child("roleRef", "apiGroup"), roleBinding.RoleRef.APIGroup, "must be 'rbac.authorization.k8s.io'")
		}

		if err := validateRBACName(roleBinding.NameSuffix, fldPath.Index(index).Child("nameSuffix")); err != nil {
			return err
		}

		// Validate the complete final binding name
		bindingName := v1alpha1.TerminalAccessResourceNamePrefix + t.Spec.Identifier + roleBinding.NameSuffix
		if err := validateRBACName(bindingName, fldPath.Index(index).Child("nameSuffix")); err != nil {
			return field.Invalid(fldPath.Index(index).Child("nameSuffix"), roleBinding.NameSuffix,
				fmt.Sprintf("complete binding name '%s' is invalid: %s", bindingName, err.Error()))
		}

		if roleBinding.BindingKind != v1alpha1.BindingKindClusterRoleBinding && roleBinding.BindingKind != v1alpha1.BindingKindRoleBinding {
			return field.Invalid(fldPath.Index(index).Child("bindingKind"), t.Spec.Target.BindingKind, "field should be either "+v1alpha1.BindingKindClusterRoleBinding.String()+" or "+v1alpha1.BindingKindRoleBinding.String())
		}

		if err := validateRoleRefForBindingKind(roleBinding.RoleRef, roleBinding.BindingKind, fldPath.Index(index).Child("roleRef")); err != nil {
			return err
		}
	}

	return validateUniqueRoleBindingNameSuffixes(t, fldPath)
}

func validateUniqueRoleBindingNameSuffixes(t *v1alpha1.Terminal, fldPath *field.Path) error {
	names := make(map[string]struct{})

	for index, roleBinding := range t.Spec.Target.Authorization.RoleBindings {
		if _, duplicate := names[roleBinding.NameSuffix]; duplicate {
			return field.Invalid(fldPath.Index(index).Child("nameSuffix"), roleBinding.NameSuffix, "name must be unique")
		}

		names[roleBinding.NameSuffix] = struct{}{}
	}

	return nil
}

func (h *TerminalValidator) validateProjectMemberships(t *v1alpha1.Terminal, fldPath *field.Path) error {
	fldPath = fldPath.Child("projectMemberships")

	for index, projectMembership := range t.Spec.Target.Authorization.ProjectMemberships {
		if !ptr.Deref(h.getConfig().HonourProjectMemberships, false) {
			return field.Forbidden(fldPath, "field is forbidden by configuration")
		}

		if err := validateRequiredField(&projectMembership.ProjectName, fldPath.Index(index).Child("projectName")); err != nil {
			return err
		}

		if err := validateDNSSubdomain(projectMembership.ProjectName, fldPath.Index(index).Child("projectName")); err != nil {
			return err
		}

		if len(projectMembership.Roles) == 0 {
			return field.Required(fldPath.Index(index).Child("roles"), "field is required")
		}

		foundRoles := make(sets.Set[string], len(projectMembership.Roles))
		for rolesIndex, role := range projectMembership.Roles {
			rolesPath := fldPath.Index(index).Child("roles").Index(rolesIndex)

			if foundRoles.Has(role) {
				return field.Duplicate(rolesPath, role)
			}

			foundRoles.Insert(role)

			if !supportedRoles.Has(role) && !strings.HasPrefix(role, extensionRolePrefix) {
				supportedRolesList := sets.List(supportedRoles)
				supportedRolesList = append(supportedRolesList, extensionRolePrefix+"*")

				return field.NotSupported(rolesPath, role, supportedRolesList)
			}

			if strings.HasPrefix(role, extensionRolePrefix) {
				extensionRoleName := strings.TrimPrefix(role, extensionRolePrefix)

				if len(extensionRoleName) > extensionRoleMaxLength {
					return field.TooLong(rolesPath, role, extensionRoleMaxLength)
				}

				// the extension role name will be used as part of a ClusterRole name
				if err := validateRBACName(extensionRoleName, rolesPath); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// canGetCredential returns true if the user can read the referenced secret and or the referenced service account and all the secrets within the namespace of the service account
func (h *TerminalValidator) canGetCredential(ctx context.Context, userInfo authenticationv1.UserInfo, cred v1alpha1.ClusterCredentials) (bool, error) {
	if allowed, err := h.canCreateShootsAdminKubeconfigAccessReview(ctx, userInfo, cred.ShootRef); err != nil {
		return false, err
	} else if !allowed {
		return false, nil
	}

	return h.canGetServiceAccountAndCreateTokenReview(ctx, userInfo, cred.ServiceAccountRef)
}

// canManageProjectMembers returns true if the user can manage ServiceAccount members for the project of the given namespace
func (h *TerminalValidator) canManageProjectMembers(ctx context.Context, userInfo authenticationv1.UserInfo, namespace string) (bool, error) {
	project, err := gardenclient.GetProjectByNamespace(ctx, h.Client, namespace)
	if err != nil {
		return false, err
	}

	return h.canManageProjectMembersAccessReview(ctx, userInfo, *project)
}

func (h *TerminalValidator) canCreateShootsAdminKubeconfigAccessReview(ctx context.Context, userInfo authenticationv1.UserInfo, ref *v1alpha1.ShootRef) (bool, error) {
	if ref == nil {
		return true, nil
	}

	subjectAccessReview := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:     gardencorev1beta1.GroupName,
				Resource:  "shoots/adminkubeconfig",
				Verb:      "create",
				Name:      ref.Name,
				Namespace: ref.Namespace,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			Extra:  toAuthZExtraValue(userInfo.Extra),
		},
	}
	err := h.Client.Create(ctx, subjectAccessReview)

	return subjectAccessReview.Status.Allowed, err
}

func (h *TerminalValidator) canGetServiceAccountAndCreateTokenReview(ctx context.Context, userInfo authenticationv1.UserInfo, serviceAccountRef *corev1.ObjectReference) (bool, error) {
	if serviceAccountRef == nil {
		return true, nil
	}

	accesReviewServiceAccount := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:     corev1.GroupName,
				Resource:  "serviceaccounts",
				Verb:      "get",
				Name:      serviceAccountRef.Name,
				Namespace: serviceAccountRef.Namespace,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			Extra:  toAuthZExtraValue(userInfo.Extra),
		},
	}

	err := h.Client.Create(ctx, accesReviewServiceAccount)
	if err != nil {
		return false, err
	}

	if !accesReviewServiceAccount.Status.Allowed {
		return false, nil
	}

	// we ensure that the user is allowed to read "all" secrets in the referenced namespace, as the secrets referenced in the service account could change over time
	accessReviewTokenRequest := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:       corev1.GroupName,
				Resource:    "serviceaccounts",
				Subresource: "token",
				Verb:        "create",
				Namespace:   serviceAccountRef.Namespace,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			Extra:  toAuthZExtraValue(userInfo.Extra),
		},
	}

	err = h.Client.Create(ctx, accessReviewTokenRequest)

	return accessReviewTokenRequest.Status.Allowed, err
}

func (h *TerminalValidator) canManageProjectMembersAccessReview(ctx context.Context, userInfo authenticationv1.UserInfo, project gardencorev1beta1.Project) (bool, error) {
	subjectAccessReview := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:    gardencorev1beta1.GroupName,
				Resource: "projects",
				Verb:     "patch", // manage-members verb is only relevant when adding/removing humans
				Name:     project.Name,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			Extra:  toAuthZExtraValue(userInfo.Extra),
		},
	}
	err := h.Client.Create(ctx, subjectAccessReview)

	return subjectAccessReview.Status.Allowed, err
}

var _ admission.Handler = &TerminalValidator{}

// Handle handles admission requests.
func (h *TerminalValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	obj := &v1alpha1.Terminal{}
	oldObj := &v1alpha1.Terminal{}

	maxObjSize := h.getConfig().Webhooks.TerminalValidation.MaxObjectSize
	objSize := len(req.Object.Raw)

	if objSize > maxObjSize {
		err := fmt.Errorf("resource must not have more than %d bytes", maxObjSize)
		h.Log.Error(err, "maxObjectSize exceeded", "objSize", objSize, "maxObjSize", maxObjSize)

		return admission.Errored(http.StatusBadRequest, err)
	}

	err := h.Decoder.Decode(req, obj)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if req.Operation != admissionv1.Create {
		err = h.Decoder.DecodeRaw(req.OldObject, oldObj)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	allowed, reason, err := h.validatingTerminalFn(ctx, obj, oldObj, req.AdmissionRequest)
	if err != nil {
		h.Log.Error(err, reason)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	if !allowed {
		h.Log.Info("admission request denied", "reason", reason)
	}

	return admission.ValidationResponse(allowed, reason)
}
