package compute

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Firewall struct {
	types.Metadata
	Name         types.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
}

type FirewallRule struct {
	types.Metadata
	Enforced types.BoolValue
	IsAllow  types.BoolValue
	Protocol types.StringValue
	Ports    []types.IntValue
}

type IngressRule struct {
	types.Metadata
	FirewallRule
	SourceRanges []types.StringValue
}

type EgressRule struct {
	types.Metadata
	FirewallRule
	DestinationRanges []types.StringValue
}
