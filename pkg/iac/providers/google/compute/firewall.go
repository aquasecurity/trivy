package compute

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Firewall struct {
	Metadata     iacTypes.Metadata
	Name         iacTypes.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
	SourceTags   []iacTypes.StringValue
	TargetTags   []iacTypes.StringValue
}

type FirewallRule struct {
	Metadata iacTypes.Metadata
	Enforced iacTypes.BoolValue
	IsAllow  iacTypes.BoolValue
	Protocol iacTypes.StringValue
	Ports    []iacTypes.IntValue
}

type IngressRule struct {
	Metadata iacTypes.Metadata
	FirewallRule
	SourceRanges []iacTypes.StringValue
}

type EgressRule struct {
	Metadata iacTypes.Metadata
	FirewallRule
	DestinationRanges []iacTypes.StringValue
}
