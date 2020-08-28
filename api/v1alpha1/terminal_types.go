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

package v1alpha1

import (
	"errors"
	"fmt"
	"time"

	"github.com/gardener/terminal-controller-manager/utils"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// TerminalSpec defines the desired state of Terminal
type TerminalSpec struct {
	Identifier string        `json:"identifier"`
	Host       HostCluster   `json:"host"`
	Target     TargetCluster `json:"target"`
}

// TerminalStatus defines the observed state of Terminal
type TerminalStatus struct {
	// AttachServiceAccountName is the name of service account on the host cluster
	AttachServiceAccountName string `json:"attachServiceAccountName"`
	// PodName is the name of the pod on the host cluster
	PodName string `json:"podName"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Terminal is the Schema for the terminals API
type Terminal struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TerminalSpec   `json:"spec,omitempty"`
	Status TerminalStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TerminalList contains a list of Terminal
type TerminalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Terminal `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Terminal{}, &TerminalList{})
}

// Host defines the desired state of the resources related to the host cluster
type HostCluster struct {
	// ClusterCredentials define the credentials to the host cluster
	Credentials ClusterCredentials `json:"credentials"`

	// Namespace is the namespace where the pod resides in
	// This field should not be set if TemporaryNamespace is set to true but must be set in case TemporaryNamespace is set to false.
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// TemporaryNamespace is a flag to indicate if the namespace should be ephemeral. If true, the namespace will be created and when the terminal is deleted, the namespace is also deleted.
	// If true, the mutating webhook makes sure that a temporary namespace is set; in this case you cannot choose the namespace
	// This field should be false if Namespace is set. You cannot define the name of the temporary namespace.
	// +optional
	TemporaryNamespace bool `json:"temporaryNamespace,omitempty"`

	Pod Pod `json:"pod"`
}

// TargetCluster defines the desired state of the resources related to the target cluster
type TargetCluster struct {
	// ClusterCredentials define the credentials to the target cluster
	Credentials ClusterCredentials `json:"credentials"`

	// Namespace is a reference to the namespace within the target cluster in which the resources should be placed.
	// This field should not be set if TemporaryNamespace is set to true
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// TemporaryNamespace is a flag to indicate if the namespace should be ephemeral. If true, the namespace will be created and when the terminal is deleted, the namespace is also deleted.
	// If true, the mutating webhook makes sure that a temporary namespace is set; in this case you cannot choose the namespace
	// This field should be false if Namespace is set. You cannot define the name of the temporary namespace.
	// +optional
	TemporaryNamespace bool `json:"temporaryNamespace,omitempty"`

	// KubeconfigContextNamespace is a reference to the namespace within the host cluster that should be used as default in the kubeconfig context
	KubeconfigContextNamespace string `json:"kubeconfigContextNamespace"`

	// APIServerServiceRef is a reference to the kube-apiserver service on the host cluster that points to the kube-apiserver of the target cluster. If no namespace is set on the object reference, it is defaulted to Spec.Host.Namespace.
	// +optional
	APIServerServiceRef *corev1.ObjectReference `json:"apiServerServiceRef,omitempty"`

	// RoleName is the name of the ClusterRole the "access" service account is bound to.
	RoleName string `json:"roleName"`

	// BindingKind defines the desired role binding. ClusterRoleBinding will result in a ClusterRoleBinding. RoleBinding will result in a RoleBinding.
	BindingKind BindingKind `json:"bindingKind"`
}

// BindingKind describes the desired role binding
// +kubebuilder:validation:Enum=ClusterRoleBinding;RoleBinding
type BindingKind string

// Pod defines the desired state of the pod
type Pod struct {
	// Map of string keys and values that can be used to organize and categorize
	// (scope and select) objects. Will be set as labels of the pod
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Container belonging to the pod.
	// Cannot be updated.
	// +optional if ContainerImage is set
	Container *Container `json:"container,omitempty"`
	// ContainerImage defines the image used for the container.
	// ContainerImage is ignored if Container is set.
	// +optional
	// Deprecated: Use `Container.Image` instead.
	ContainerImage string `json:"containerImage,omitempty"`
	// Run container in privileged mode.
	// Privileged is ignored if Container is set.
	// Processes in privileged containers are essentially equivalent to root on the host.
	// Defaults to false.
	// +optional
	// Deprecated: Use `Container.Privileged` instead.
	Privileged bool `json:"privileged,omitempty"`
	// Host networking requested for this pod. Use the host's network namespace.
	// Default to false.
	// +optional
	HostNetwork bool `json:"hostNetwork,omitempty"`
	// Use the host's pid namespace.
	// Default to false.
	// +optional
	HostPID bool `json:"hostPID,omitempty"`
	// NodeSelector is a selector which must be true for the pod to fit on a node.
	// Selector which must match a node's labels for the pod to be scheduled on that node.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// A single application container that you want to run within a pod.
type Container struct {
	// Image defines the image used for the container.
	// As this image is also used for the "setup" init container, the `/bin/cp` binary has to be part of the image
	Image string `json:"image"`
	// Entrypoint array. Not executed within a shell.
	// The docker image's ENTRYPOINT is used if this is not provided.
	// Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
	// cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
	// can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
	// regardless of whether the variable exists or not.
	// Cannot be updated.
	// More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
	// +optional
	Command []string `json:"command,omitempty"`
	// Arguments to the entrypoint.
	// The docker image's CMD is used if this is not provided.
	// Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
	// cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
	// can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
	// regardless of whether the variable exists or not.
	// Cannot be updated.
	// More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
	// +optional
	Args []string `json:"args,omitempty"`
	// Compute Resources required by this container.
	// Cannot be updated.
	// More info: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// Run container in privileged mode.
	// Processes in privileged containers are essentially equivalent to root on the host.
	// Defaults to false.
	// +optional
	Privileged bool `json:"privileged,omitempty"`
}

// ClusterCredentials define the credentials for a kubernetes cluster
type ClusterCredentials struct {
	// SecretRef is a reference to a secret that contains the cluster specific credentials
	// Either SecretRef or ServiceAccountRef is mandatory. SecretRef will be used if both refs are provided.
	// +optional
	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`

	// ServiceAccountRef is a reference to a service account that should be used, usually to manage resources on the same cluster as the service account is residing in
	// +optional
	ServiceAccountRef *corev1.ObjectReference `json:"serviceAccountRef,omitempty"`
}

// LastError indicates the last occurred error for an operation on a resource.
type LastError struct {
	// A human readable message indicating details about the last error.
	Description string `json:"description"`
	// Well-defined error codes of the last error(s).
	// +optional
	Codes []ErrorCode `json:"codes,omitempty"`
}

// ErrorCode is a string alias.
type ErrorCode string

// ControllerManagerConfiguration defines the configuration for the Gardener controller manager.
type ControllerManagerConfiguration struct {
	// +optional
	Kind string `yaml:"kind"`
	// +optional
	APIVersion string `yaml:"apiVersion"`

	// Controllers defines the configuration of the controllers.
	Controllers ControllerManagerControllerConfiguration `yaml:"controllers"`
	// Webhooks defines the configuration of the admission webhooks.
	Webhooks ControllerManagerWebhookConfiguration `yaml:"webhooks"`
	// Logger defines the configuration of the zap logging module.
	Logger ControllerManagerLoggerConfiguration `yaml:"logger"`
}

// ControllerManagerLogger defines the configuration of the Zap Logger.
type ControllerManagerLoggerConfiguration struct {
	// If Development is true, a Zap development config will be used
	// (stacktraces on warnings, no sampling), otherwise a Zap production
	// config will be used (stacktraces on errors, sampling). Defaults to true.
	Development bool `yaml:"development"`
}

// ControllerManagerControllerConfiguration defines the configuration of the controllers.
type ControllerManagerControllerConfiguration struct {
	// Terminal defines the configuration of the Terminal controller.
	Terminal TerminalControllerConfiguration `yaml:"terminal"`
	// TerminalHeartbeat defines the configuration of the TerminalHeartbeat controller.
	TerminalHeartbeat TerminalHeartbeatControllerConfiguration `yaml:"terminalHeartbeat"`
}

// TerminalControllerConfiguration defines the configuration of the Terminal controller.
type TerminalControllerConfiguration struct {
	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 15.
	MaxConcurrentReconciles int `yaml:"maxConcurrentReconciles"`

	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run per Namespace (independent of the user who created the Terminal resource). Defaults to 3.
	MaxConcurrentReconcilesPerNamespace int `yaml:"maxConcurrentReconcilesPerNamespace"`
}

// TerminalHeartbeatControllerConfiguration defines the configuration of the TerminalHeartbeat controller.
type TerminalHeartbeatControllerConfiguration struct {
	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 1.
	MaxConcurrentReconciles int `yaml:"maxConcurrentReconciles"`

	// TimeToLive is the duration a Terminal resource can live without receiving a heartbeat with the "dashboard.gardener.cloud/operation=keepalive" annotation. Defaults to 5m.
	TimeToLive Duration `yaml:"timeToLive"`
}

// Duration is a wrapper around time.Duration which supports correct
// marshaling to YAML. In particular, it marshals into strings, which
// can be used as map keys in json.
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements the yaml.Unmarshaller interface.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}

	t, err := time.ParseDuration(str)
	if err != nil {
		return fmt.Errorf("failed to parse '%s' to time.Duration: %v", str, err)
	}

	d.Duration = t

	return nil
}

// ControllerManagerWebhookConfiguration defines the configuration of the admission webhooks.
type ControllerManagerWebhookConfiguration struct {
	// TerminalValidation defines the configuration of the validating webhook.
	TerminalValidation TerminalValidatingWebhookConfiguration `yaml:"terminalValidation"`
}

// TerminalValidatingWebhookConfiguration defines the configuration of the validating webhook.
type TerminalValidatingWebhookConfiguration struct {
	// MaxObjectSize is the maximum size of a terminal resource in bytes. Defaults to 10240.
	MaxObjectSize int `yaml:"maxObjectSize"`
}

func (t *Terminal) NewLabelsSet() (*labels.Set, error) {
	if len(t.Spec.Identifier) == 0 {
		return nil, errors.New("identifier not set")
	}

	if t.Spec.Target.Namespace == nil {
		return nil, errors.New("target namespace not set")
	}

	if len(t.ObjectMeta.Annotations[GardenCreatedBy]) == 0 {
		return nil, errors.New("createdBy annotation not set")
	}

	targetNamespaceHash, err := utils.ToFnvHash(*t.Spec.Target.Namespace)
	if err != nil {
		return nil, err
	}

	createdByHash, err := utils.ToFnvHash(t.ObjectMeta.Annotations[GardenCreatedBy])
	if err != nil {
		return nil, err
	}

	return &labels.Set{
		Component: TerminalComponent,
		"terminal.dashboard.gardener.cloud/identifier":      t.Spec.Identifier,
		"terminal.dashboard.gardener.cloud/target-ns-hash":  targetNamespaceHash,
		"terminal.dashboard.gardener.cloud/created-by-hash": createdByHash,
	}, nil
}

func (t *Terminal) NewAnnotationsSet() (*utils.Set, error) {
	if t.Spec.Target.Namespace == nil {
		return nil, errors.New("target namespace not set")
	}

	if len(t.ObjectMeta.Annotations[GardenCreatedBy]) == 0 {
		return nil, errors.New("createdBy annotation not set")
	}

	targetNamespace := *t.Spec.Target.Namespace
	createdBy := t.ObjectMeta.Annotations[GardenCreatedBy]

	return &utils.Set{
		"terminal.dashboard.gardener.cloud/target-ns":  targetNamespace,
		"terminal.dashboard.gardener.cloud/created-by": createdBy,
	}, nil
}

const (
	// TerminalName is the value in a Terminal resource's `.metadata.finalizers[]` array on which the Terminal controller will react
	// when performing a delete request on a resource.
	TerminalName = "terminal"

	// Component is the label key for the component
	Component = "component"

	// TerminalComponent is the component name of the terminal controller manager. All resources created by the terminal controller will have this label
	TerminalComponent = "terminal-controller-manager"

	// GardenCreatedBy is the key for an annotation of a terminal resource whose value contains the username
	// of the user that created the resource.
	GardenCreatedBy = "gardener.cloud/created-by"

	// TerminalLastHeartbeat is the key for an annotation of a terminal resource whose value contains the username
	// of the user that created the resource.
	TerminalLastHeartbeat = "dashboard.gardener.cloud/last-heartbeat-at"

	// ShootOperation is a constant for an annotation on a Shoot in a failed state indicating that an operation shall be performed.
	TerminalOperation = "dashboard.gardener.cloud/operation"

	// ShootOperationMaintain is a constant for an annotation on a Shoot indicating that the Shoot maintenance shall be executed as soon as
	// possible.
	TerminalOperationKeepalive = "keepalive"

	// EventReconciling indicates that a Reconcile operation started.
	EventReconciling = "Reconciling"
	// EventReconciled indicates that a Reconcile operation was successful.
	EventReconciled = "Reconciled"
	// EventReconcileError indicates that a Reconcile operation failed.
	EventReconcileError = "ReconcileError"
	// EventDeleting indicates that a Delete operation started.
	EventDeleting = "Deleting"
	// EventDeleted indicates that a Delete operation was successful.
	EventDeleted = "Deleted"
	// EventDeleteError indicates that a Delete operation failed.
	EventDeleteError = "DeleteError"

	// BindingKindClusterRoleBinding will result in a ClusterRoleBinding
	BindingKindClusterRoleBinding BindingKind = "ClusterRoleBinding"
	// BindingKindRoleBinding  will result in a RoleBinding
	BindingKindRoleBinding BindingKind = "RoleBinding"

	// KubeconfigSecretResourceNamePrefix is a name prefix for the kubeconfig secret used within the terminal pod.
	KubeconfigSecretResourceNamePrefix = "term-kubeconfig-"

	// TerminalAttachResourceNamePrefix is a name prefix for resources related to attach to the terminal pod.
	TerminalAttachResourceNamePrefix = "term-attach-"

	// TerminalAccessResourceNamePrefix is a name prefix for resources related to accessing the target cluster.
	TerminalAccessResourceNamePrefix = "term-access-"

	// TerminalPodResourceNamePrefix is a name prefix for the terminal pod
	TerminalPodResourceNamePrefix = "term-"

	// TerminalAttachRoleResourceNamePrefix is a name prefix for the role allowing to attach to the terminal pod
	TerminalAttachRoleResourceNamePrefix = "dashboard.gardener.cloud:term-attach-"
)
