/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package webhooks

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/utils"
)

// TerminalMutator handles Terminal
type TerminalMutator struct {
	client client.Client
	Log    logr.Logger

	// Decoder decodes objects
	decoder *admission.Decoder
}

func (h *TerminalMutator) mutatingTerminalFn(ctx context.Context, t *v1alpha1.Terminal, admissionReq admissionv1.AdmissionRequest) error {
	if t.ObjectMeta.Annotations == nil {
		t.ObjectMeta.Annotations = map[string]string{}
	}

	if admissionReq.Operation == admissionv1.Create {
		t.ObjectMeta.Annotations[v1alpha1.GardenCreatedBy] = admissionReq.UserInfo.Username

		uuid := uuid.NewUUID()

		terminalIdentifier, err := utils.ToFnvHash(string(uuid))
		if err != nil {
			return err
		}

		t.Spec.Identifier = terminalIdentifier

		h.mutateNamespaceIfTemporary(t, terminalIdentifier)

		t.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat] = time.Now().UTC().Format(time.RFC3339)
	}

	if t.ObjectMeta.Annotations[v1alpha1.TerminalOperation] == v1alpha1.TerminalOperationKeepalive {
		delete(t.ObjectMeta.Annotations, v1alpha1.TerminalOperation)
		t.ObjectMeta.Annotations[v1alpha1.TerminalLastHeartbeat] = time.Now().UTC().Format(time.RFC3339)
	}

	return nil
}

func (h *TerminalMutator) mutateNamespaceIfTemporary(t *v1alpha1.Terminal, terminalIdentifier string) {
	if pointer.BoolDeref(t.Spec.Host.TemporaryNamespace, false) {
		ns := "term-host-" + terminalIdentifier
		t.Spec.Host.Namespace = &ns
	}

	if pointer.BoolDeref(t.Spec.Target.TemporaryNamespace, false) {
		ns := "term-target-" + terminalIdentifier
		t.Spec.Target.Namespace = &ns
	}
}

var _ admission.Handler = &TerminalMutator{}

// Handle handles admission requests.
func (h *TerminalMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	obj := &v1alpha1.Terminal{}

	err := h.decoder.Decode(req, obj)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	copy := obj.DeepCopy()

	err = h.mutatingTerminalFn(ctx, copy, req.AdmissionRequest)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	marshaledTerminal, err := json.Marshal(copy)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledTerminal)
}

var _ inject.Client = &TerminalMutator{}

// A client will be automatically injected.

// InjectClient injects the client.
func (h *TerminalMutator) InjectClient(c client.Client) error {
	h.client = c
	return nil
}

// TerminalMutator implements admission.DecoderInjector.
// A decoder will be automatically injected.

// InjectDecoder injects the decoder.
func (h *TerminalMutator) InjectDecoder(d *admission.Decoder) error {
	h.decoder = d
	return nil
}
