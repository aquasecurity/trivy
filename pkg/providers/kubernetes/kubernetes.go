package kubernetes

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Kubernetes struct {
	NetworkPolicies []NetworkPolicy
}

type NetworkPolicy struct {
	Metadata defsecTypes.MisconfigMetadata
	Spec     NetworkPolicySpec
}

type NetworkPolicySpec struct {
	Metadata defsecTypes.MisconfigMetadata
	Egress   Egress
	Ingress  Ingress
}

type Egress struct {
	Metadata         defsecTypes.MisconfigMetadata
	Ports            []Port
	DestinationCIDRs []defsecTypes.StringValue
}

type Ingress struct {
	Metadata    defsecTypes.MisconfigMetadata
	Ports       []Port
	SourceCIDRs []defsecTypes.StringValue
}

type Port struct {
	Metadata defsecTypes.MisconfigMetadata
	Number   defsecTypes.StringValue // e.g. "http" or "80"
	Protocol defsecTypes.StringValue
}
