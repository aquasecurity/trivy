package network

import (
	"github.com/google/uuid"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/set"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
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
		NetworkInterfaces:      adaptNetworkInterfaces(modules),
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
		Enabled:  resource.GetAttribute("enabled").AsBoolValueOrDefault(false, resource),
		RetentionPolicy: network.RetentionPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			Days:     iacTypes.IntDefault(0, resource.GetMetadata()),
		},
	}

	if retentionPolicyBlock := resource.GetBlock("retention_policy"); retentionPolicyBlock.IsNotNil() {
		flowLog.RetentionPolicy = network.RetentionPolicy{
			Metadata: retentionPolicyBlock.GetMetadata(),
			Enabled: retentionPolicyBlock.GetAttribute("enabled").
				AsBoolValueOrDefault(false, retentionPolicyBlock),
			Days: retentionPolicyBlock.GetAttribute("days").
				AsIntValueOrDefault(0, retentionPolicyBlock),
		}
	}
	return flowLog
}

func adaptNetworkInterfaces(modules terraform.Modules) []network.NetworkInterface {
	var networkInterfaces []network.NetworkInterface

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_interface") {
			networkInterfaces = append(networkInterfaces, AdaptNetworkInterface(resource, modules))
		}
	}

	return networkInterfaces
}

func AdaptNetworkInterface(resource *terraform.Block, modules terraform.Modules) network.NetworkInterface {
	ni := network.NetworkInterface{
		Metadata: resource.GetMetadata(),
		// Support both ip_forwarding_enabled (new) and enable_ip_forwarding (old) attributes
		EnableIPForwarding: resource.GetFirstAttributeOf("ip_forwarding_enabled", "enable_ip_forwarding").
			AsBoolValueOrDefault(false, resource),
		HasPublicIP:     iacTypes.BoolDefault(false, resource.GetMetadata()),
		PublicIPAddress: iacTypes.StringDefault("", resource.GetMetadata()),
		SubnetID:        iacTypes.StringDefault("", resource.GetMetadata()),
	}

	ni.SecurityGroups = resolveNetworkInterfaceSecurityGroups(resource, modules)

	ipConfigs := resource.GetBlocks("ip_configuration")
	ni.IPConfigurations = make([]network.IPConfiguration, 0, len(ipConfigs))
	for _, ipConfig := range ipConfigs {
		ni.IPConfigurations = append(ni.IPConfigurations, network.IPConfiguration{
			Metadata:        ipConfig.GetMetadata(),
			PublicIPAddress: ipConfig.GetAttribute("public_ip_address_id").AsStringValueOrDefault("", ipConfig),
			SubnetID:        ipConfig.GetAttribute("subnet_id").AsStringValueOrDefault("", ipConfig),
			Primary:         ipConfig.GetAttribute("primary").AsBoolValueOrDefault(false, ipConfig),
		})
	}

	ni.Setup()
	return ni
}

func resolveNetworkInterfaceSecurityGroups(resource *terraform.Block, modules terraform.Modules) []network.SecurityGroup {
	associations := modules.GetReferencingResources(
		resource,
		"azurerm_network_interface_security_group_association",
		"network_interface_id",
	)
	seen := set.New[string]()
	securityGroups := make([]network.SecurityGroup, 0, len(associations)+1)

	addSecurityGroup := func(attr *terraform.Attribute, parent *terraform.Block) {
		if attr == nil || attr.IsNil() {
			return
		}

		referencedNSG, err := modules.GetReferencedBlock(attr, parent)
		if err != nil || referencedNSG == nil {
			return
		}

		if seen.Contains(referencedNSG.ID()) {
			return
		}
		seen.Append(referencedNSG.ID())
		securityGroups = append(securityGroups, adaptSecurityGroupFromBlock(referencedNSG))
	}

	// Backward compatibility for deprecated inline NIC NSG association.
	addSecurityGroup(resource.GetAttribute("network_security_group_id"), resource)

	// Current provider behavior uses explicit association resources.
	for _, association := range associations {
		addSecurityGroup(association.GetAttribute("network_security_group_id"), association)
	}

	if len(securityGroups) == 0 {
		return nil
	}

	return securityGroups
}

func adaptSecurityGroupFromBlock(resource *terraform.Block) network.SecurityGroup {
	return network.SecurityGroup{
		Metadata: resource.GetMetadata(),
		Rules:    xslices.Map(resource.GetBlocks("security_rule"), AdaptSGRule),
	}
}
