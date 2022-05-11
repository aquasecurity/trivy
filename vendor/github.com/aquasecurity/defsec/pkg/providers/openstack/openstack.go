package openstack

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type OpenStack struct {
	Compute    Compute
	Networking Networking
}

type Compute struct {
	Instances []Instance
	Firewall  Firewall
}

type Firewall struct {
	types.Metadata
	AllowRules []FirewallRule
	DenyRules  []FirewallRule
}

type FirewallRule struct {
	types.Metadata
	Source          types.StringValue
	Destination     types.StringValue
	SourcePort      types.StringValue
	DestinationPort types.StringValue
	Enabled         types.BoolValue
}

type Instance struct {
	types.Metadata
	AdminPassword types.StringValue
}
