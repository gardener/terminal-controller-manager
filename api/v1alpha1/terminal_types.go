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
	// This field should not be set if TemporaryNamespace is set to true
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
	// ContainerImage defines the image used for the container.
	ContainerImage string `json:"containerImage"`
	// Run container in privileged mode.
	// Processes in privileged containers are essentially equivalent to root on the host.
	// Defaults to false.
	// +optional
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

	targetNamespace, err := utils.ToFnvHash(*t.Spec.Target.Namespace)
	if err != nil {
		return nil, err
	}

	createdByHash, err := utils.ToFnvHash(t.ObjectMeta.Annotations["garden.sapcloud.io/createdBy"])
	if err != nil {
		return nil, err
	}

	return &labels.Set{
		Component: TerminalComponent,
		"terminal.dashboard.gardener.cloud/identifier":    t.Spec.Identifier,
		"terminal.dashboard.gardener.cloud/targetNsHash":  targetNamespace,
		"terminal.dashboard.gardener.cloud/createdByHash": createdByHash,
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
	GardenCreatedBy = "garden.sapcloud.io/createdBy"

	// GardenCreatedBy is the key for an annotation of a terminal resource whose value contains the username
	// of the user that created the resource.
	TerminalLastHeartbeat = "dashboard.gardener.cloud/lastHeartbeatAt"

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
