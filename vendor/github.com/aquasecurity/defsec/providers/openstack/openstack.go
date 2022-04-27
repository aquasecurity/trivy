package openstack

import "github.com/aquasecurity/defsec/parsers/types"

type OpenStack struct {
	types.Metadata
	Compute    Compute
	Networking Networking
}

type Compute struct {
	types.Metadata
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
