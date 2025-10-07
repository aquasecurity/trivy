package openstack

import (
	"github.com/google/uuid"

	"github.com/aquasecurity/trivy/pkg/iac/providers/openstack"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptNetworking(modules terraform.Modules) openstack.Networking {
	return openstack.Networking{
		SecurityGroups: adaptSecurityGroups(modules),
	}
}

func adaptSecurityGroups(modules terraform.Modules) []openstack.SecurityGroup {
	groupMap := make(map[string]openstack.SecurityGroup)
	for _, groupBlock := range modules.GetResourcesByType("openstack_networking_secgroup_v2") {
		group := openstack.SecurityGroup{
			Metadata:    groupBlock.GetMetadata(),
			Name:        groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock),
			Description: groupBlock.GetAttribute("description").AsStringValueOrDefault("", groupBlock),
			Rules:       nil,
		}
		groupMap[groupBlock.ID()] = group
	}

	for _, ruleBlock := range modules.GetResourcesByType("openstack_networking_secgroup_rule_v2") {
		rule := openstack.SecurityGroupRule{
			Metadata:  ruleBlock.GetMetadata(),
			IsIngress: iacTypes.Bool(true, ruleBlock.GetMetadata()),
			EtherType: iacTypes.IntDefault(4, ruleBlock.GetMetadata()),
			Protocol:  ruleBlock.GetAttribute("protocol").AsStringValueOrDefault("tcp", ruleBlock),
			PortMin:   ruleBlock.GetAttribute("port_range_min").AsIntValueOrDefault(0, ruleBlock),
			PortMax:   ruleBlock.GetAttribute("port_range_max").AsIntValueOrDefault(0, ruleBlock),
			CIDR:      ruleBlock.GetAttribute("remote_ip_prefix").AsStringValueOrDefault("", ruleBlock),
		}

		switch etherType := ruleBlock.GetAttribute("ethertype"); {
		case etherType.Equals("IPv4"):
			rule.EtherType = iacTypes.Int(4, etherType.GetMetadata())
		case etherType.Equals("IPv6"):
			rule.EtherType = iacTypes.Int(6, etherType.GetMetadata())
		}

		switch direction := ruleBlock.GetAttribute("direction"); {
		case direction.Equals("egress"):
			rule.IsIngress = iacTypes.Bool(false, direction.GetMetadata())
		case direction.Equals("ingress"):
			rule.IsIngress = iacTypes.Bool(true, direction.GetMetadata())
		}

		groupID := ruleBlock.GetAttribute("security_group_id")
		if refBlock, err := modules.GetReferencedBlock(groupID, ruleBlock); err == nil {
			if group, ok := groupMap[refBlock.ID()]; ok {
				group.Rules = append(group.Rules, rule)
				groupMap[refBlock.ID()] = group
				continue
			}
		}

		group := openstack.SecurityGroup{
			Metadata:    iacTypes.NewUnmanagedMetadata(),
			Name:        iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			Description: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			Rules:       []openstack.SecurityGroupRule{rule},
		}
		groupMap[uuid.NewString()] = group

	}

	var groups []openstack.SecurityGroup
	for _, group := range groupMap {
		groups = append(groups, group)
	}
	return groups
}
