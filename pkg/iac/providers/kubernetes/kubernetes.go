package kubernetes

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Kubernetes struct {
	NetworkPolicies []NetworkPolicy
}

type NetworkPolicy struct {
	Metadata defsecTypes.Metadata
	Spec     NetworkPolicySpec
}

type NetworkPolicySpec struct {
	Metadata defsecTypes.Metadata
	Egress   Egress
	Ingress  Ingress
}

type Egress struct {
	Metadata         defsecTypes.Metadata
	Ports            []Port
	DestinationCIDRs []defsecTypes.StringValue
}

type Ingress struct {
	Metadata    defsecTypes.Metadata
	Ports       []Port
	SourceCIDRs []defsecTypes.StringValue
}

type Port struct {
	Metadata defsecTypes.Metadata
	Number   defsecTypes.StringValue // e.g. "http" or "80"
	Protocol defsecTypes.StringValue
}
