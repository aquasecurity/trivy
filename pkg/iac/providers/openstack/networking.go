package openstack

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Networking struct {
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	Metadata    iacTypes.Metadata
	Name        iacTypes.StringValue
	Description iacTypes.StringValue
	Rules       []SecurityGroupRule
}

// SecurityGroupRule describes https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
type SecurityGroupRule struct {
	Metadata  iacTypes.Metadata
	IsIngress iacTypes.BoolValue
	EtherType iacTypes.IntValue    // 4 or 6 for ipv4/ipv6
	Protocol  iacTypes.StringValue // e.g. tcp
	PortMin   iacTypes.IntValue
	PortMax   iacTypes.IntValue
	CIDR      iacTypes.StringValue
}
