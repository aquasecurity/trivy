package network

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/parsers/terraform"

	"github.com/aquasecurity/defsec/providers/azure/network"

	"github.com/google/uuid"
)

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
		rule := a.adaptSGRule(ruleBlock)

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
			Metadata: types.NewUnmanagedMetadata(),
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
		rules = append(rules, a.adaptSGRule(ruleBlock))
	}
	a.groups[resource.ID()] = network.SecurityGroup{
		Metadata: resource.GetMetadata(),
		Rules:    rules,
	}
}

func (a *adapter) adaptSGRule(ruleBlock *terraform.Block) network.SecurityGroupRule {

	rule := network.SecurityGroupRule{
		Metadata:             ruleBlock.GetMetadata(),
		Outbound:             types.BoolDefault(false, ruleBlock.GetMetadata()),
		Allow:                types.BoolDefault(true, ruleBlock.GetMetadata()),
		SourceAddresses:      nil,
		SourcePorts:          nil,
		DestinationAddresses: nil,
		DestinationPorts:     nil,
	}

	accessAttr := ruleBlock.GetAttribute("access")
	if accessAttr.Equals("Allow") {
		rule.Allow = types.Bool(true, accessAttr.GetMetadata())
	} else if accessAttr.Equals("Deny") {
		rule.Allow = types.Bool(false, accessAttr.GetMetadata())
	}

	directionAttr := ruleBlock.GetAttribute("direction")
	if directionAttr.Equals("Inbound") {
		rule.Outbound = types.Bool(false, directionAttr.GetMetadata())
	} else if directionAttr.Equals("Outbound") {
		rule.Outbound = types.Bool(true, directionAttr.GetMetadata())
	}

	a.adaptSource(ruleBlock, &rule)
	a.adaptDestination(ruleBlock, &rule)

	return rule
}

func (a *adapter) adaptSource(ruleBlock *terraform.Block, rule *network.SecurityGroupRule) {
	if sourceAddressAttr := ruleBlock.GetAttribute("source_address_prefix"); sourceAddressAttr.IsString() {
		rule.SourceAddresses = append(rule.SourceAddresses, sourceAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if sourceAddressPrefixesAttr := ruleBlock.GetAttribute("source_address_prefixes"); sourceAddressPrefixesAttr.IsNotNil() {
		for _, prefix := range sourceAddressPrefixesAttr.ValueAsStrings() {
			rule.SourceAddresses = append(rule.SourceAddresses, types.String(prefix, sourceAddressPrefixesAttr.GetMetadata()))
		}
	}

	if sourcePortRangesAttr := ruleBlock.GetAttribute("source_port_ranges"); sourcePortRangesAttr.IsNotNil() {
		for _, value := range sourcePortRangesAttr.ValueAsStrings() {
			rule.SourcePorts = append(rule.SourcePorts, expandRange(value, sourcePortRangesAttr.GetMetadata()))
		}
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsString() {
		rule.SourcePorts = append(rule.SourcePorts, expandRange(sourcePortRangeAttr.Value().AsString(), sourcePortRangeAttr.GetMetadata()))
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsNumber() {
		bf := sourcePortRangeAttr.Value().AsBigFloat()
		f, _ := bf.Float64()
		rule.SourcePorts = append(rule.SourcePorts, network.PortRange{
			Metadata: sourcePortRangeAttr.GetMetadata(),
			Start:    int(f),
			End:      int(f),
		})
	}
}

func (a *adapter) adaptDestination(ruleBlock *terraform.Block, rule *network.SecurityGroupRule) {
	if destAddressAttr := ruleBlock.GetAttribute("destination_address_prefix"); destAddressAttr.IsString() {
		rule.DestinationAddresses = append(rule.DestinationAddresses, destAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if destAddressPrefixesAttr := ruleBlock.GetAttribute("destination_address_prefixes"); destAddressPrefixesAttr.IsNotNil() {
		for _, prefix := range destAddressPrefixesAttr.ValueAsStrings() {
			rule.DestinationAddresses = append(rule.DestinationAddresses, types.String(prefix, destAddressPrefixesAttr.GetMetadata()))
		}
	}

	if destPortRangesAttr := ruleBlock.GetAttribute("destination_port_ranges"); destPortRangesAttr.IsNotNil() {
		for _, value := range destPortRangesAttr.ValueAsStrings() {
			rule.DestinationPorts = append(rule.DestinationPorts, expandRange(value, destPortRangesAttr.GetMetadata()))
		}
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsString() {
		rule.DestinationPorts = append(rule.DestinationPorts, expandRange(destPortRangeAttr.Value().AsString(), destPortRangeAttr.GetMetadata()))
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsNumber() {
		bf := destPortRangeAttr.Value().AsBigFloat()
		f, _ := bf.Float64()
		rule.DestinationPorts = append(rule.DestinationPorts, network.PortRange{
			Metadata: destPortRangeAttr.GetMetadata(),
			Start:    int(f),
			End:      int(f),
		})
	}
}

func expandRange(r string, m types.Metadata) network.PortRange {
	start := 0
	end := 65535
	switch {
	case r == "*":
	case strings.Contains(r, "-"):
		if parts := strings.Split(r, "-"); len(parts) == 2 {
			if p1, err := strconv.ParseInt(parts[0], 10, 32); err == nil {
				start = int(p1)
			}
			if p2, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
				end = int(p2)
			}
		}
	default:
		if val, err := strconv.ParseInt(r, 10, 32); err == nil {
			start = int(val)
			end = int(val)
		}
	}

	return network.PortRange{
		Metadata: m,
		Start:    start,
		End:      end,
	}
}

func adaptWatcherLog(resource *terraform.Block) network.NetworkWatcherFlowLog {
	flowLog := network.NetworkWatcherFlowLog{
		Metadata: resource.GetMetadata(),
		RetentionPolicy: network.RetentionPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			Days:     types.IntDefault(0, resource.GetMetadata()),
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
