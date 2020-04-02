package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type JwkerSpec struct {
	Cluster      string        `json:"cluster"`
	AccessPolicy *AccessPolicy `json:"accessPolicy,omitempty"`
}
type AccessPolicy struct {
	Inbound  *AccessPolicyInbound  `json:"inbound,omitempty"`
	Outbound *AccessPolicyOutbound `json:"outbound,omitempty"`
}
type AccessPolicyOutbound struct {
	Rules []AccessPolicyRule `json:"rules,omitempty"`
}
type AccessPolicyInbound struct {
	Rules []AccessPolicyRule `json:"rules"`
}
type AccessPolicyRule struct {
	Application string `json:"application"`
	Namespace   string `json:"namespace,omitempty"`
	Cluster     string `json:"clustername,omitempty"`
}

// JwkerStatus defines the observed state of Jwker
type JwkerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true

// Jwker is the Schema for the jwkers API
type Jwker struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   JwkerSpec   `json:"spec,omitempty"`
	Status JwkerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// JwkerList contains a list of Jwker
type JwkerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Jwker `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Jwker{}, &JwkerList{})
}
