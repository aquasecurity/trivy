package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Firewall struct {
	Metadata     defsecTypes.Metadata
	Name         defsecTypes.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
	SourceTags   []defsecTypes.StringValue
	TargetTags   []defsecTypes.StringValue
}

type FirewallRule struct {
	Metadata defsecTypes.Metadata
	Enforced defsecTypes.BoolValue
	IsAllow  defsecTypes.BoolValue
	Protocol defsecTypes.StringValue
	Ports    []defsecTypes.IntValue
}

type IngressRule struct {
	Metadata defsecTypes.Metadata
	FirewallRule
	SourceRanges []defsecTypes.StringValue
}

type EgressRule struct {
	Metadata defsecTypes.Metadata
	FirewallRule
	DestinationRanges []defsecTypes.StringValue
}
