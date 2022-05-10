package openstack

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Networking struct {
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	types.Metadata
	Name        types.StringValue
	Description types.StringValue
	Rules       []SecurityGroupRule
}

// SecurityGroupRule describes https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
type SecurityGroupRule struct {
	types.Metadata
	IsIngress types.BoolValue
	EtherType types.IntValue    // 4 or 6 for ipv4/ipv6
	Protocol  types.StringValue // e.g. tcp
	PortMin   types.IntValue
	PortMax   types.IntValue
	CIDR      types.StringValue
}
