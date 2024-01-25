package openstack

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Networking struct {
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	Metadata    defsecTypes.MisconfigMetadata
	Name        defsecTypes.StringValue
	Description defsecTypes.StringValue
	Rules       []SecurityGroupRule
}

// SecurityGroupRule describes https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
type SecurityGroupRule struct {
	Metadata  defsecTypes.MisconfigMetadata
	IsIngress defsecTypes.BoolValue
	EtherType defsecTypes.IntValue    // 4 or 6 for ipv4/ipv6
	Protocol  defsecTypes.StringValue // e.g. tcp
	PortMin   defsecTypes.IntValue
	PortMax   defsecTypes.IntValue
	CIDR      defsecTypes.StringValue
}
