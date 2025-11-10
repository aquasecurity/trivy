package network

import (
	"github.com/google/uuid"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func parsePortRange(input string, meta iacTypes.Metadata) common.PortRange {
	return common.ParsePortRange(input, meta, common.WithWildcard())
}

func Adapt(modules terraform.Modules) network.Network {
	return network.Network{
		SecurityGroups: (&adapter{
			modules: modules,
			groups:  make(map[string]network.SecurityGroup),
		}).adaptSecurityGroups(),
		NetworkWatcherFlowLogs: adaptWatcherLogs(modules),
	}
}

type adapter struct {
	modules terraform.Modules
	groups  map[string]network.SecurityGroup
}

func (a *adapter) adaptSecurityGroups() []network.SecurityGroup {

	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_security_group") {
			a.adaptSecurityGroup(resource)
		}
	}

	for _, ruleBlock := range a.modules.GetResourcesByType("azurerm_network_security_rule") {
		rule := AdaptSGRule(ruleBlock)

		groupAttr := ruleBlock.GetAttribute("network_security_group_name")
		if groupAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(groupAttr, ruleBlock); err == nil {
				if group, ok := a.groups[referencedBlock.ID()]; ok {
					group.Rules = append(group.Rules, rule)
					a.groups[referencedBlock.ID()] = group
					continue
				}
			}

		}

		a.groups[uuid.NewString()] = network.SecurityGroup{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Rules:    []network.SecurityGroupRule{rule},
		}
	}

	var securityGroups []network.SecurityGroup
	for _, group := range a.groups {
		securityGroups = append(securityGroups, group)
	}

	return securityGroups
}

func adaptWatcherLogs(modules terraform.Modules) []network.NetworkWatcherFlowLog {
	var watcherLogs []network.NetworkWatcherFlowLog

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_watcher_flow_log") {
			watcherLogs = append(watcherLogs, adaptWatcherLog(resource))
		}
	}
	return watcherLogs
}

func (a *adapter) adaptSecurityGroup(resource *terraform.Block) {
	var rules []network.SecurityGroupRule
	for _, ruleBlock := range resource.GetBlocks("security_rule") {
		rules = append(rules, AdaptSGRule(ruleBlock))
	}
	a.groups[resource.ID()] = network.SecurityGroup{
		Metadata: resource.GetMetadata(),
		Rules:    rules,
	}
}

func adaptWatcherLog(resource *terraform.Block) network.NetworkWatcherFlowLog {
	flowLog := network.NetworkWatcherFlowLog{
		Metadata: resource.GetMetadata(),
		RetentionPolicy: network.RetentionPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			Days:     iacTypes.IntDefault(0, resource.GetMetadata()),
		},
	}

	if retentionPolicyBlock := resource.GetBlock("retention_policy"); retentionPolicyBlock.IsNotNil() {
		flowLog.RetentionPolicy.Metadata = retentionPolicyBlock.GetMetadata()

		enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
		flowLog.RetentionPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, retentionPolicyBlock)

		daysAttr := retentionPolicyBlock.GetAttribute("days")
		flowLog.RetentionPolicy.Days = daysAttr.AsIntValueOrDefault(0, retentionPolicyBlock)
	}

	return flowLog
}
