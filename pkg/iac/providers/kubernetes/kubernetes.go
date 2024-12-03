package kubernetes

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Kubernetes struct {
	NetworkPolicies []NetworkPolicy
}

type NetworkPolicy struct {
	Metadata iacTypes.Metadata
	Spec     NetworkPolicySpec
}

type NetworkPolicySpec struct {
	Metadata iacTypes.Metadata
	Egress   Egress
	Ingress  Ingress
}

type Egress struct {
	Metadata         iacTypes.Metadata
	Ports            []Port
	DestinationCIDRs []iacTypes.StringValue
}

type Ingress struct {
	Metadata    iacTypes.Metadata
	Ports       []Port
	SourceCIDRs []iacTypes.StringValue
}

type Port struct {
	Metadata iacTypes.Metadata
	Number   iacTypes.StringValue // e.g. "http" or "80"
	Protocol iacTypes.StringValue
}
