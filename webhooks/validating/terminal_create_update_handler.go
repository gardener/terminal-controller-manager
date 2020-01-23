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

package validating

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// TerminalValidator handles Terminal
type TerminalValidator struct {
	client client.Client
	Log    logr.Logger
	Config *v1alpha1.ControllerManagerConfiguration

	// Decoder decodes objects
	decoder *admission.Decoder
}

func (h *TerminalValidator) validatingTerminalFn(ctx context.Context, t *v1alpha1.Terminal, oldT *v1alpha1.Terminal, admissionReq v1beta1.AdmissionRequest) (bool, string, error) {
	userInfo := admissionReq.UserInfo

	if admissionReq.Operation != v1beta1.Create {
		// TODO write unit tests where we explicitly check that the identifier and the secretRefs cannot be changed
		specFldPath := field.NewPath("spec")
		if err := validateImmutableField(t.Spec, oldT.Spec, specFldPath); err != nil {
			return false, err.Error(), nil
		}

		createdByFldPath := field.NewPath("metadata", "annotations", v1alpha1.GardenCreatedBy)
		if err := validateImmutableField(t.ObjectMeta.Annotations[v1alpha1.GardenCreatedBy], oldT.ObjectMeta.Annotations[v1alpha1.GardenCreatedBy], createdByFldPath); err != nil {
			return false, err.Error(), nil
		}

		// only same user is allowed to keep terminal session alive
		changedBySameUser := t.ObjectMeta.Annotations[v1alpha1.GardenCreatedBy] == admissionReq.UserInfo.Username
		if t.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat] != oldT.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat] && !changedBySameUser {
			return false, field.Forbidden(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), "you are not allowed to change this field").Error(), nil
		}
	}

	lastHeartbeat := t.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat]
	if len(lastHeartbeat) > 0 {
		lastHeartBeatParsed, err := time.Parse(time.RFC3339, lastHeartbeat)
		if err != nil {
			return false, field.Invalid(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), t.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat], "failed to parse time").Error(), nil
		}

		if lastHeartBeatParsed.After(time.Now().UTC()) {
			return false, field.Forbidden(field.NewPath("metadata", "annotations", v1alpha1.TerminalLastHeartbeat), "time must not be in the future").Error(), nil
		}
	}

	fldValidations := getFieldValidations(t)
	if err := validateRequiredFields(fldValidations); err != nil {
		return false, err.Error(), nil
	}

	if err := validateRequiredCredentials(t); err != nil {
		return false, err.Error(), nil
	}

	if allowed, err := h.canGetCredential(ctx, userInfo, t.Spec.Target.Credentials); err != nil {
		return false, err.Error(), nil
	} else if !allowed {
		return false, field.Forbidden(field.NewPath("spec", "target", "credentials"), "you are not allowed to read target credential").Error(), nil
	}

	if allowed, err := h.canGetCredential(ctx, userInfo, t.Spec.Host.Credentials); err != nil {
		return false, err.Error(), nil
	} else if !allowed {
		return false, field.Forbidden(field.NewPath("spec", "host", "credentials"), "you are not allowed to read host credential").Error(), nil
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
			value:   &t.Spec.Target.RoleName,
			fldPath: field.NewPath("spec", "target", "roleName"),
		},
		{
			value:   &t.Spec.Target.KubeconfigContextNamespace,
			fldPath: field.NewPath("spec", "target", "kubeconfigContextNamespace"),
		},
		{
			value:   &t.Spec.Host.Pod.ContainerImage,
			fldPath: field.NewPath("spec", "host", "pod", "containerImage"),
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

func validateRequiredCredentials(t *v1alpha1.Terminal) error {
	if err := validateRequiredCredential(t.Spec.Target.Credentials, field.NewPath("spec", "target", "credentials")); err != nil {
		return err
	}

	return validateRequiredCredential(t.Spec.Host.Credentials, field.NewPath("spec", "host", "credentials"))
}

func validateRequiredCredential(cred v1alpha1.ClusterCredentials, fldPath *field.Path) error {
	if cred.SecretRef == nil && cred.ServiceAccountRef == nil {
		return field.Required(fldPath, "field requires either SecretRef or ServiceAccountRef to be set")
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

// canGetCredential returns true if the user can read the referenced secret and or the referenced service account and all the secrets within the namespace of the service account
func (h *TerminalValidator) canGetCredential(ctx context.Context, userInfo v1.UserInfo, cred v1alpha1.ClusterCredentials) (bool, error) {
	if allowed, err := h.canGetSecretAccessReview(ctx, userInfo, cred.SecretRef); err != nil {
		return false, err
	} else if !allowed {
		return false, nil
	}

	return h.canGetServiceAccountAndSecretAccessReview(ctx, userInfo, cred.ServiceAccountRef)
}

func (h *TerminalValidator) canGetSecretAccessReview(ctx context.Context, userInfo v1.UserInfo, ref *corev1.SecretReference) (bool, error) {
	if ref == nil {
		return true, nil
	}

	subjectAccessReview := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Group:     corev1.GroupName,
				Resource:  corev1.ResourceSecrets.String(),
				Verb:      "get",
				Name:      ref.Name,
				Namespace: ref.Namespace,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			// Extra:  userInfo.Extra, // TODO convert / cast
		},
	}
	err := h.client.Create(ctx, subjectAccessReview)

	return subjectAccessReview.Status.Allowed, err
}

func (h *TerminalValidator) canGetServiceAccountAndSecretAccessReview(ctx context.Context, userInfo v1.UserInfo, serviceAccountRef *corev1.ObjectReference) (bool, error) {
	if serviceAccountRef == nil {
		return true, nil
	}

	accesReviewServiceAccount := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Group:     corev1.GroupName,
				Resource:  "serviceaccounts",
				Verb:      "get",
				Name:      serviceAccountRef.Name,
				Namespace: serviceAccountRef.Namespace,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			// Extra:  userInfo.Extra, // TODO convert / cast
		},
	}

	err := h.client.Create(ctx, accesReviewServiceAccount)
	if err != nil {
		return false, err
	}

	if !accesReviewServiceAccount.Status.Allowed {
		return false, nil
	}

	// we ensure that the user is allowed to read "all" secrets in the referenced namespace, as the secrets referenced in the service account could change over time
	accessReviewSecret := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Group:     corev1.GroupName,
				Resource:  corev1.ResourceSecrets.String(),
				Verb:      "get",
				Namespace: serviceAccountRef.Namespace,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			// Extra:  userInfo.Extra, // TODO convert / cast
		},
	}
	err = h.client.Create(ctx, accessReviewSecret)

	return accessReviewSecret.Status.Allowed, err
}

var _ admission.Handler = &TerminalValidator{}

// Handle handles admission requests.
func (h *TerminalValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	obj := &v1alpha1.Terminal{}
	oldObj := &v1alpha1.Terminal{}

	maxObjSize := h.Config.Webhooks.TerminalValidation.MaxObjectSize
	objSize := len(req.Object.Raw)

	if objSize > maxObjSize {
		err := fmt.Errorf("resource must not have more than %d bytes", maxObjSize)
		h.Log.Error(err, "maxObjectSize exceeded", "objSize", objSize, "maxObjSize", maxObjSize)

		return admission.Errored(http.StatusBadRequest, err)
	}

	err := h.decoder.Decode(req, obj)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if req.AdmissionRequest.Operation != v1beta1.Create {
		err = h.decoder.DecodeRaw(req.AdmissionRequest.OldObject, oldObj)
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

var _ inject.Client = &TerminalValidator{}

// A client will be automatically injected.

// InjectClient injects the client.
func (h *TerminalValidator) InjectClient(c client.Client) error {
	h.client = c
	return nil
}

// TerminalValidator implements admission.DecoderInjector.
// A decoder will be automatically injected.

// InjectDecoder injects the decoder.
func (h *TerminalValidator) InjectDecoder(d *admission.Decoder) error {
	h.decoder = d
	return nil
}
