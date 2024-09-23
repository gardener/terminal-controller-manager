/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"

	"github.com/gardener/terminal-controller-manager/internal/utils"
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
	// +optional
	AttachServiceAccountName *string `json:"attachServiceAccountName,omitempty"`
	// PodName is the name of the pod on the host cluster
	// +optional
	PodName *string `json:"podName,omitempty"`
	// LastOperation indicates the type and the state of the last operation, along with a description message.
	// +optional
	LastOperation *LastOperation `json:"lastOperation,omitempty"`
	// LastError contains details about the last error that occurred.
	// +optional
	LastError *LastError `json:"lastError,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="app.kubernetes.io/name=terminal";"app.kubernetes.io/component=controller-manager"

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

// HostCluster defines the desired state of the resources related to the host cluster
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
	TemporaryNamespace *bool `json:"temporaryNamespace,omitempty"`

	Pod Pod `json:"pod"`
}

// TargetCluster defines the desired state of the resources related to the target cluster
type TargetCluster struct {
	// ClusterCredentials define the credentials to the target cluster
	Credentials ClusterCredentials `json:"credentials"`

	// CleanupProjectMembership indicates if the service account referenced by credentials.serviceAccountRef should be removed as project member if not referenced anymore by a Terminal resource.
	// If true, the credentials.serviceAccountRef.namespace must be the same as the Terminal resource.
	// +optional
	CleanupProjectMembership *bool `json:"cleanupProjectMembership,omitempty"`

	// Namespace is a reference to the namespace within the target cluster in which the resources should be placed.
	// This field should not be set if TemporaryNamespace is set to true
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// TemporaryNamespace is a flag to indicate if the namespace should be ephemeral. If true, the namespace will be created and when the terminal is deleted, the namespace is also deleted.
	// If true, the mutating webhook makes sure that a temporary namespace is set; in this case you cannot choose the namespace
	// This field should be false if Namespace is set. You cannot define the name of the temporary namespace.
	// +optional
	TemporaryNamespace *bool `json:"temporaryNamespace,omitempty"`

	// KubeconfigContextNamespace is a reference to the namespace within the host cluster that should be used as default in the kubeconfig context
	KubeconfigContextNamespace string `json:"kubeconfigContextNamespace"`

	// APIServerServiceRef is a reference to the kube-apiserver service on the host cluster that points to the kube-apiserver of the target cluster. If no namespace is set on the object reference, it is defaulted to Spec.Host.Namespace.
	// +optional
	// Deprecated: use APIServer.ServiceRef instead
	APIServerServiceRef *corev1.ObjectReference `json:"apiServerServiceRef,omitempty"`

	// APIServer references the kube-apiserver of the target cluster.
	// +optional
	APIServer *APIServer `json:"apiServer,omitempty"`

	// RoleName is the name of the ClusterRole the "access" service account is bound to.
	// +optional
	// Deprecated: use Authorization.RoleBindings[].RoleRef.NameSuffix instead
	RoleName string `json:"roleName,omitempty"`

	// BindingKind defines the desired role binding. ClusterRoleBinding will result in a ClusterRoleBinding. RoleBinding will result in a RoleBinding.
	// +optional
	// Deprecated: use Authorization.RoleBindings[].BindingKind instead
	BindingKind BindingKind `json:"bindingKind,omitempty"`

	Authorization *Authorization `json:"authorization,omitempty"`
}

// Authorization the desired (temporary) privileges the "access" service account should receive.
// Either rbac role bindings can be defined, or the service account can be added as member to a gardener project with specific roles. In the latter case, gardener manages the rbac.
type Authorization struct {
	// RoleBindings defines the desired (temporary) rbac role bindings the "access" service account should be assigned to
	// +optional
	RoleBindings []RoleBinding `json:"roleBindings,omitempty"`

	// ProjectMemberships defines the (temporary) project memberships of the "access" service account. Each project is updated by using the target.credential, hence the target has the be the (virtual) garden cluster.
	// +optional
	ProjectMemberships []ProjectMembership `json:"projectMemberships,omitempty"`
}

type RoleBinding struct {
	// NameSuffix is the name suffix of the temporary (Cluster)RoleBinding that will be created. NameSuffix should be unique
	NameSuffix string `json:"nameSuffix"`

	// RoleRef can reference a Role in the current namespace or a ClusterRole in the global namespace.
	RoleRef rbacv1.RoleRef `json:"roleRef"`

	// BindingKind defines the desired role binding. ClusterRoleBinding will result in a ClusterRoleBinding. RoleBinding will result in a RoleBinding.
	BindingKind BindingKind `json:"bindingKind"`
}

// ProjectMembership defines the (temporary) project membership of the "access" service account. The project is updated by using the target.credential, hence the target has the be the (virtual) garden cluster.
type ProjectMembership struct {
	// ProjectName is the name of the project, the "access" service account should be member of
	ProjectName string `json:"projectName"`

	// Roles defines the gardener roles the "access" service account should receive, e.g. admin, viewer, uam.
	Roles []string `json:"roles"`
}

// APIServer references the kube-apiserver.
type APIServer struct {
	// ServiceRef is a reference to the kube-apiserver service on the host cluster that points to the kube-apiserver of the target cluster. If no namespace is set on the object reference, it is defaulted to Spec.Host.Namespace.
	// +optional
	ServiceRef *corev1.ObjectReference `json:"serviceRef,omitempty"`

	// Server is the address of the target kubernetes cluster (https://hostname:port). The address should be accessible from the terminal pod within the host cluster.
	// +optional
	Server string `json:"server,omitempty"`

	// CAData holds PEM-encoded bytes (typically read from a root certificates bundle).
	// +optional
	// +nullable
	CAData []byte `json:"caData"`
}

// BindingKind describes the desired role binding
// +kubebuilder:validation:Enum=ClusterRoleBinding;RoleBinding;""
type BindingKind string

func (c BindingKind) String() string {
	return string(c)
}

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
	// ServiceAccountRef is a reference to a service account that should be used, usually to manage resources on the same cluster as the service account is residing in
	// Either ShootRef or ServiceAccountRef is mandatory. ShootRef will be used if more than one ref is provided.
	// +optional
	ServiceAccountRef *corev1.ObjectReference `json:"serviceAccountRef,omitempty"`

	// ShootRef references the shoot cluster. The admin kubeconfig retrieved from the shoots/adminkubeconfig endpoint is used
	// Either ShootRef or ServiceAccountRef is mandatory. ShootRef will be used if more than one ref is provided.
	// +optional
	ShootRef *ShootRef `json:"shootRef,omitempty"`
}

// ShootRef references the shoot cluster by namespace and name
type ShootRef struct {
	// Namespace is the namespace of the shoot cluster
	Namespace string `json:"namespace"`
	// Name is the name of the shoot cluster
	Name string `json:"name"`
}

// LastError indicates the last occurred error for an operation on a resource.
type LastError struct {
	// Description is a human-readable message indicating details about the last error.
	Description string `json:"description"`
	// Last time the error was reported
	// +optional
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`
}

// ErrorCode is a string alias.
type ErrorCode string

// ControllerManagerConfiguration defines the configuration for the Gardener controller manager.
type ControllerManagerConfiguration struct {
	// +optional
	Kind string `json:"kind"`
	// +optional
	APIVersion string `json:"apiVersion"`

	// Server defines the configuration of the HTTP server.
	Server ServerConfiguration `json:"server"`

	// Controllers defines the configuration of the controllers.
	Controllers ControllerManagerControllerConfiguration `json:"controllers"`
	// Webhooks defines the configuration of the admission webhooks.
	Webhooks ControllerManagerWebhookConfiguration `json:"webhooks"`
	// HonourServiceAccountRefHostCluster defines if `host.credentials.serviceAccountRef` property should be honoured.
	// It is recommended to be set to false for multi-cluster setups, in case pods are refused on the (virtual) garden cluster where the terminal resources are stored.
	// Defaults to true.
	// +optional
	HonourServiceAccountRefHostCluster *bool `json:"honourServiceAccountRefHostCluster,omitempty"`
	// HonourServiceAccountRefTargetCluster defines if `target.credentials.serviceAccountRef` property should be honoured.
	// Defaults to true.
	// +optional
	HonourServiceAccountRefTargetCluster *bool `json:"honourServiceAccountRefTargetCluster,omitempty"`
	// HonourProjectMemberships defines if `target.authorization.projectMemberships` property should be honoured.
	// It is recommended to be set to false in case no gardener API server extension is registered for the (virtual) garden cluster where the terminal resources are stored.
	// Defaults to true.
	// +optional
	HonourProjectMemberships *bool `json:"honourProjectMemberships,omitempty"`
	// HonourCleanupProjectMembership defines if `target.credential.serviceAccountRef.cleanupProjectMembership` property should be honoured.
	// It is recommended to be set to false in case no gardener API server extension is registered for the (virtual) garden cluster where the terminal resources are stored.
	// Defaults to false.
	// +optional
	HonourCleanupProjectMembership *bool `json:"honourCleanupProjectMembership,omitempty"`

	// LeaderElection defines the configuration of leader election client.
	// +optional
	LeaderElection *componentbaseconfigv1alpha1.LeaderElectionConfiguration `json:"leaderElection,omitempty"`
}

// ServerConfiguration contains details for the HTTP(S) servers.
type ServerConfiguration struct {
	// HealthProbes is the configuration for serving the healthz and readyz endpoints.
	HealthProbes *Server `json:"healthProbes"`
	// Metrics is the configuration for serving the metrics endpoint.
	Metrics *Server `json:"metrics"`
}

// Server contains information for HTTP(S) server configuration.
type Server struct {
	// BindAddress is the IP address on which to listen for the specified port.
	BindAddress string `json:"bindAddress"`
	// Port is the port on which to serve requests.
	Port int `json:"port"`
}

// ControllerManagerControllerConfiguration defines the configuration of the controllers.
type ControllerManagerControllerConfiguration struct {
	// Terminal defines the configuration of the Terminal controller.
	Terminal TerminalControllerConfiguration `json:"terminal"`
	// TerminalHeartbeat defines the configuration of the TerminalHeartbeat controller.
	TerminalHeartbeat TerminalHeartbeatControllerConfiguration `json:"terminalHeartbeat"`
	// ServiceAccount defines the configuration of the ServiceAccount controller.
	ServiceAccount ServiceAccountControllerConfiguration `json:"serviceAccount"`
}

// TerminalControllerConfiguration defines the configuration of the Terminal controller.
type TerminalControllerConfiguration struct {
	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 15.
	MaxConcurrentReconciles int `json:"maxConcurrentReconciles"`

	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run per Namespace (independent of the user who created the Terminal resource). Defaults to 3.
	MaxConcurrentReconcilesPerNamespace int `json:"maxConcurrentReconcilesPerNamespace"`

	// TokenRequestExpirationSeconds is the requested duration of validity of the access token request.
	// The token issuer may return a token with a different validity duration.
	TokenRequestExpirationSeconds *int64 `json:"tokenRequestExpirationSeconds"`
}

// TerminalHeartbeatControllerConfiguration defines the configuration of the TerminalHeartbeat controller.
type TerminalHeartbeatControllerConfiguration struct {
	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 1.
	MaxConcurrentReconciles int `json:"maxConcurrentReconciles"`

	// TimeToLive is the duration a Terminal resource can live without receiving a heartbeat with the "dashboard.gardener.cloud/operation=keepalive" annotation. Defaults to 5m.
	TimeToLive Duration `json:"timeToLive"`
}

// ServiceAccountControllerConfiguration defines the configuration of the ServiceAccount controller.
type ServiceAccountControllerConfiguration struct {
	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles which can be run. Defaults to 1.
	MaxConcurrentReconciles int `json:"maxConcurrentReconciles"`

	// AllowedServiceAccountNames is a list of service account names that are allowed to be cleaned up as project members.
	// If the list is empty all names are considered as allowed
	AllowedServiceAccountNames []string `json:"allowedServiceAccountNames"`
}

// LastOperation indicates the type and the state of the last operation, along with a description
// message.
type LastOperation struct {
	// A human-readable message indicating details about the last operation.
	Description string `json:"description"`
	// Last time the operation state transitioned from one to another.
	LastUpdateTime metav1.Time `json:"lastUpdateTime"`
	// Status of the last operation, one of Processing, Succeeded, Error.
	State LastOperationState `json:"state"`
	// Type of the last operation, one of Reconcile, Delete.
	Type LastOperationType `json:"type"`
}

// Duration is a wrapper around time.Duration which supports correct
// marshaling to YAML. In particular, it marshals into strings, which
// can be used as map keys in json.
type Duration struct {
	time.Duration
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *Duration) UnmarshalJSON(bytes []byte) error {
	var str string
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}

	t, err := time.ParseDuration(str)
	if err != nil {
		return fmt.Errorf("failed to parse '%s' to time.Duration: %v", str, err)
	}

	d.Duration = t

	return nil
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
	TerminalValidation TerminalValidatingWebhookConfiguration `json:"terminalValidation"`
}

// TerminalValidatingWebhookConfiguration defines the configuration of the validating webhook.
type TerminalValidatingWebhookConfiguration struct {
	// MaxObjectSize is the maximum size of a terminal resource in bytes. Defaults to 10240.
	MaxObjectSize int `json:"maxObjectSize"`
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

	// ExternalTerminalName is the value in a Kubernetes core resources `.metadata.finalizers[]` array on which the
	// Terminal will react when performing a delete request on a resource.
	ExternalTerminalName = "gardener.cloud/terminal"

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

	// TerminalOperation is a constant for an annotation on a Terminal indicating that an operation shall be performed.
	TerminalOperation = "dashboard.gardener.cloud/operation"

	// TerminalReference is a label used to identify service accounts which are referred by a target or host .credential.serviceAccountRef of a Terminal (necessarily in the same namespace).
	// and for which cleanupProjectMembership is set to true
	TerminalReference = "reference.dashboard.gardener.cloud/terminal"

	// Description is the key for an annotation whose value contains the description for this resource
	// of the user that created the resource.
	Description = "dashboard.gardener.cloud/description"

	// TerminalOperationKeepalive is a constant for an annotation on a Terminal indicating that the Terminal should be kept alive for a certain period of time.
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

	// TokenSecretResourceNamePrefix is a name prefix for the token secret that is mounted to the terminal pod.
	TokenSecretResourceNamePrefix = "term-token-"

	// TerminalAttachResourceNamePrefix is a name prefix for resources related to attach to the terminal pod.
	TerminalAttachResourceNamePrefix = "term-attach-"

	// TerminalAccessResourceNamePrefix is a name prefix for resources related to accessing the target cluster.
	TerminalAccessResourceNamePrefix = "term-access-"

	// TerminalPodResourceNamePrefix is a name prefix for the terminal pod
	TerminalPodResourceNamePrefix = "term-"

	// TerminalAttachRoleResourceNamePrefix is a name prefix for the role allowing to attach to the terminal pod
	TerminalAttachRoleResourceNamePrefix = "dashboard.gardener.cloud:term-attach-"
)

// LastOperationType is a string alias.
type LastOperationType string

const (
	// LastOperationTypeReconcile indicates a 'reconcile' operation.
	LastOperationTypeReconcile LastOperationType = "Reconcile"
	// LastOperationTypeDelete indicates a 'delete' operation.
	LastOperationTypeDelete LastOperationType = "Delete"
)

type LastOperationState string

// LastOperationState is a string alias.
const (
	// LastOperationStateProcessing indicates that an operation is ongoing.
	LastOperationStateProcessing LastOperationState = "Processing"
	// LastOperationStateSucceeded indicates that an operation has completed successfully.
	LastOperationStateSucceeded LastOperationState = "Succeeded"
	// LastOperationStateError indicates that an operation is completed with errors and will be retried.
	LastOperationStateError LastOperationState = "Error"
)
