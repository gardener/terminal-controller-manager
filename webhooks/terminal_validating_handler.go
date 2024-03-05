/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package webhooks

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
)

// TerminalValidator handles Terminal
type TerminalValidator struct {
	Client      client.Client
	Log         logr.Logger
	Config      *v1alpha1.ControllerManagerConfiguration
	configMutex sync.RWMutex

	// Decoder decodes objects
	Decoder *admission.Decoder
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
		if err := validateImmutableField(t.ObjectMeta.Annotations[v1alpha1.GardenCreatedBy], oldT.ObjectMeta.Annotations[v1alpha1.GardenCreatedBy], createdByFldPath); err != nil {
			return false, err.Error(), nil
		}

		// only same user is allowed to keep terminal session alive
		userFromAnnotations := t.ObjectMeta.Annotations[v1alpha1.GardenCreatedBy]
		changedBySameUser := userFromAnnotations == admissionReq.UserInfo.Username

		if t.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat] != oldT.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat] && !changedBySameUser {
			return false, field.Forbidden(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), userInfo.Username+" is not allowed to change this field").Error(), nil
		}
	}

	lastHeartbeat := t.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat]
	if len(lastHeartbeat) > 0 {
		lastHeartBeatParsed, err := time.Parse(time.RFC3339, lastHeartbeat)
		if err != nil {
			return false, field.Invalid(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), lastHeartbeat, "failed to parse time").Error(), nil
		}

		if lastHeartBeatParsed.After(time.Now().UTC()) {
			return false, field.Forbidden(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), "time must not be in the future").Error(), nil
		}
	}

	fldValidations := getFieldValidations(t)
	if err := validateRequiredFields(fldValidations); err != nil {
		return false, err.Error(), nil
	}

	if err := validateRequiredPodFields(t); err != nil {
		return false, err.Error(), nil
	}

	if err := h.validateRequiredCredentials(t); err != nil {
		return false, err.Error(), nil
	}

	if err := h.validateRequiredTargetAuthorization(t); err != nil {
		return false, err.Error(), nil
	}

	if err := validateRequiredAPIServerFields(t); err != nil {
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

func getFieldValidations(t *v1alpha1.Terminal) *[]fldValidation {
	fldValidations := &[]fldValidation{
		{
			value:   t.Spec.Target.Namespace, // The mutating webhook ensures that a target namespace is always set
			fldPath: field.NewPath("spec", "target", "namespace"),
		},
		{
			value:   t.Spec.Host.Namespace, // The mutating webhook ensures that a host namespace is set in case TemporaryNamespace is true
			fldPath: field.NewPath("spec", "host", "namespace"),
		},
		{
			value:   &t.Spec.Target.KubeconfigContextNamespace,
			fldPath: field.NewPath("spec", "target", "kubeconfigContextNamespace"),
		},
	}

	return fldValidations
}

type fldValidation struct {
	value   *string
	fldPath *field.Path
}

func validateRequiredFields(fldValidations *[]fldValidation) error {
	for _, fldValidation := range *fldValidations {
		if err := validateRequiredField(fldValidation.value, fldValidation.fldPath); err != nil {
			return err
		}
	}

	return nil
}

func validateRequiredField(val *string, fldPath *field.Path) error {
	if val == nil || len(*val) == 0 {
		return field.Required(fldPath, "field is required")
	}

	return nil
}

func validateImmutableField(newVal, oldVal interface{}, fldPath *field.Path) error {
	if !equality.Semantic.DeepEqual(oldVal, newVal) {
		return field.Invalid(fldPath, newVal, validation.FieldImmutableErrorMsg)
	}

	return nil
}

func validateRequiredPodFields(t *v1alpha1.Terminal) error {
	if len(t.Spec.Host.Pod.ContainerImage) == 0 {
		return validateRequiredContainerFields(t.Spec.Host.Pod.Container, field.NewPath("spec", "host", "pod", "container"))
	}

	return nil
}

func validateRequiredContainerFields(container *v1alpha1.Container, fldPath *field.Path) error {
	if container == nil {
		return field.Required(fldPath, "field is required")
	}

	return validateRequiredField(&container.Image, fldPath.Child("image"))
}

func validateRequiredAPIServerFields(t *v1alpha1.Terminal) error {
	if t.Spec.Target.APIServerServiceRef != nil {
		return validateRequiredField(&t.Spec.Target.APIServerServiceRef.Name, field.NewPath("spec", "target", "apiServerServiceRef", "name"))
	}

	if t.Spec.Target.APIServer != nil {
		if t.Spec.Target.APIServer.ServiceRef != nil {
			return validateRequiredField(&t.Spec.Target.APIServer.ServiceRef.Name, field.NewPath("spec", "target", "apiServer", "serviceRef", "name"))
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

func (h *TerminalValidator) validateRequiredCredentials(t *v1alpha1.Terminal) error {
	if err := validateRequiredCredential(t.Spec.Target.Credentials, field.NewPath("spec", "target", "credentials"), h.getConfig().HonourServiceAccountRefTargetCluster); err != nil {
		return err
	}

	return validateRequiredCredential(t.Spec.Host.Credentials, field.NewPath("spec", "host", "credentials"), h.getConfig().HonourServiceAccountRefHostCluster)
}

func validateRequiredCredential(cred v1alpha1.ClusterCredentials, fldPath *field.Path, honourServiceAccountRef *bool) error {
	if !ptr.Deref(honourServiceAccountRef, false) {
		if cred.ServiceAccountRef != nil {
			return field.Forbidden(fldPath.Child("serviceAccountRef"), "field is forbidden by configuration")
		}

		if cred.ShootRef == nil && cred.SecretRef == nil {
			return field.Required(fldPath.Child("secretRef"), "field requires either ShootRef or SecretRef to be set")
		}
	} else {
		if cred.ShootRef == nil && cred.SecretRef == nil && cred.ServiceAccountRef == nil {
			return field.Required(fldPath, "field requires either ShootRef, SecretRef or ServiceAccountRef to be set")
		}
	}

	if cred.ShootRef != nil {
		fldValidations := &[]fldValidation{
			{
				value:   &cred.ShootRef.Name,
				fldPath: fldPath.Child("shootRef", "name"),
			},
			{
				value:   &cred.ShootRef.Namespace,
				fldPath: fldPath.Child("shootRef", "namespace"),
			},
		}
		if err := validateRequiredFields(fldValidations); err != nil {
			return err
		}
	}

	if cred.SecretRef != nil {
		fldValidations := &[]fldValidation{
			{
				value:   &cred.SecretRef.Name,
				fldPath: fldPath.Child("secretRef", "name"),
			},
			{
				value:   &cred.SecretRef.Namespace,
				fldPath: fldPath.Child("secretRef", "namespace"),
			},
		}
		if err := validateRequiredFields(fldValidations); err != nil {
			return err
		}
	}

	if cred.ServiceAccountRef != nil {
		fldValidations := &[]fldValidation{
			{
				value:   &cred.ServiceAccountRef.Name,
				fldPath: fldPath.Child("serviceAccountRef", "name"),
			},
			{
				value:   &cred.ServiceAccountRef.Namespace,
				fldPath: fldPath.Child("serviceAccountRef", "namespace"),
			},
		}
		if err := validateRequiredFields(fldValidations); err != nil {
			return err
		}
	}

	return nil
}

func (h *TerminalValidator) validateRequiredTargetAuthorization(t *v1alpha1.Terminal) error {
	fldPath := field.NewPath("spec", "target")

	if t.Spec.Target.RoleName != "" {
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

		if roleBinding.BindingKind != v1alpha1.BindingKindClusterRoleBinding && roleBinding.BindingKind != v1alpha1.BindingKindRoleBinding {
			return field.Invalid(fldPath.Index(index).Child("bindingKind"), t.Spec.Target.BindingKind, "field should be either "+v1alpha1.BindingKindClusterRoleBinding.String()+" or "+v1alpha1.BindingKindRoleBinding.String())
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

		if len(projectMembership.Roles) == 0 {
			return field.Required(fldPath.Index(index).Child("roles"), "field is required")
		}

		for rolesIndex, role := range projectMembership.Roles {
			if err := validateRequiredField(&role, fldPath.Index(index).Child("roles").Index(rolesIndex)); err != nil {
				return err
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

	if allowed, err := h.canGetSecretAccessReview(ctx, userInfo, cred.SecretRef); err != nil {
		return false, err
	} else if !allowed {
		return false, nil
	}

	return h.canGetServiceAccountAndSecretAccessReview(ctx, userInfo, cred.ServiceAccountRef)
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

func (h *TerminalValidator) canGetSecretAccessReview(ctx context.Context, userInfo authenticationv1.UserInfo, ref *corev1.SecretReference) (bool, error) {
	if ref == nil {
		return true, nil
	}

	subjectAccessReview := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:     corev1.GroupName,
				Resource:  corev1.ResourceSecrets.String(),
				Verb:      "get",
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

func (h *TerminalValidator) canGetServiceAccountAndSecretAccessReview(ctx context.Context, userInfo authenticationv1.UserInfo, serviceAccountRef *corev1.ObjectReference) (bool, error) {
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
	accessReviewSecret := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:     corev1.GroupName,
				Resource:  corev1.ResourceSecrets.String(),
				Verb:      "get",
				Namespace: serviceAccountRef.Namespace,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			Extra:  toAuthZExtraValue(userInfo.Extra),
		},
	}
	err = h.Client.Create(ctx, accessReviewSecret)

	return accessReviewSecret.Status.Allowed, err
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

	if req.AdmissionRequest.Operation != admissionv1.Create {
		err = h.Decoder.DecodeRaw(req.AdmissionRequest.OldObject, oldObj)
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
