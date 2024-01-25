package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Firewall struct {
	Metadata     defsecTypes.MisconfigMetadata
	Name         defsecTypes.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
	SourceTags   []defsecTypes.StringValue
	TargetTags   []defsecTypes.StringValue
}

type FirewallRule struct {
	Metadata defsecTypes.MisconfigMetadata
	Enforced defsecTypes.BoolValue
	IsAllow  defsecTypes.BoolValue
	Protocol defsecTypes.StringValue
	Ports    []defsecTypes.IntValue
}

type IngressRule struct {
	Metadata defsecTypes.MisconfigMetadata
	FirewallRule
	SourceRanges []defsecTypes.StringValue
}

type EgressRule struct {
	Metadata defsecTypes.MisconfigMetadata
	FirewallRule
	DestinationRanges []defsecTypes.StringValue
}
