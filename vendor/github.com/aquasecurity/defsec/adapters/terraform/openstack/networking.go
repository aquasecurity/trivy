package openstack

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/openstack"
	"github.com/google/uuid"
)

func adaptNetworking(modules terraform.Modules) openstack.Networking {
	return openstack.Networking{
		SecurityGroups: adaptSecurityGroups(modules),
	}
}

func adaptSecurityGroups(modules terraform.Modules) []openstack.SecurityGroup {
	groupMap := make(map[string]openstack.SecurityGroup)
	for _, groupBlock := range modules.GetResourcesByType("openstack_networking_secgroup_v2") {
		var group openstack.SecurityGroup
		group.Metadata = groupBlock.GetMetadata()
		group.Name = groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock)
		group.Description = groupBlock.GetAttribute("description").AsStringValueOrDefault("", groupBlock)
		groupMap[groupBlock.ID()] = group
	}

	for _, ruleBlock := range modules.GetResourcesByType("openstack_networking_secgroup_rule_v2") {
		var rule openstack.SecurityGroupRule
		rule.Metadata = ruleBlock.GetMetadata()

		rule.CIDR = ruleBlock.GetAttribute("remote_ip_prefix").AsStringValueOrDefault("", ruleBlock)
		switch etherType := ruleBlock.GetAttribute("ethertype"); {
		case etherType.Equals("IPv4"):
			rule.EtherType = types.Int(4, etherType.GetMetadata())
		case etherType.Equals("IPv6"):
			rule.EtherType = types.Int(6, etherType.GetMetadata())
		default:
			rule.EtherType = types.IntDefault(4, ruleBlock.GetMetadata())
		}

		switch direction := ruleBlock.GetAttribute("direction"); {
		case direction.Equals("egress"):
			rule.IsIngress = types.Bool(false, direction.GetMetadata())
		case direction.Equals("ingress"):
			rule.IsIngress = types.Bool(true, direction.GetMetadata())
		default:
			rule.IsIngress = types.Bool(true, ruleBlock.GetMetadata())
		}

		rule.Protocol = ruleBlock.GetAttribute("protocol").AsStringValueOrDefault("tcp", ruleBlock)

		rule.PortMin = ruleBlock.GetAttribute("port_range_min").AsIntValueOrDefault(0, ruleBlock)
		rule.PortMax = ruleBlock.GetAttribute("port_range_max").AsIntValueOrDefault(0, ruleBlock)

		groupID := ruleBlock.GetAttribute("security_group_id")
		if refBlock, err := modules.GetReferencedBlock(groupID, ruleBlock); err == nil {
			if group, ok := groupMap[refBlock.ID()]; ok {
				group.Rules = append(group.Rules, rule)
				groupMap[refBlock.ID()] = group
				continue
			}
		}

		var group openstack.SecurityGroup
		group.Metadata = types.NewUnmanagedMetadata()
		group.Rules = append(group.Rules, rule)
		groupMap[uuid.NewString()] = group

	}

	var groups []openstack.SecurityGroup
	for _, group := range groupMap {
		groups = append(groups, group)
	}
	return groups
}
