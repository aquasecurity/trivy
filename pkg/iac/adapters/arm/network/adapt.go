package network

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func parsePortRange(input string, meta iacTypes.Metadata) common.PortRange {
	return common.ParsePortRange(input, meta, common.WithWildcard())
}

func Adapt(deployment azure.Deployment) network.Network {
	return network.Network{
		SecurityGroups:         adaptSecurityGroups(deployment),
		NetworkWatcherFlowLogs: adaptNetworkWatcherFlowLogs(deployment),
	}
}

func adaptSecurityGroups(deployment azure.Deployment) (sgs []network.SecurityGroup) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Network/networkSecurityGroups") {
		sgs = append(sgs, adaptSecurityGroup(resource, deployment))
	}
	return sgs

}

func adaptSecurityGroup(resource azure.Resource, deployment azure.Deployment) network.SecurityGroup {
	return network.SecurityGroup{
		Metadata: resource.Metadata,
		Rules:    adaptSecurityGroupRules(deployment),
	}
}

func adaptSecurityGroupRules(deployment azure.Deployment) (rules []network.SecurityGroupRule) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Network/networkSecurityGroups/securityRules") {
		rules = append(rules, adaptSecurityGroupRule(resource))
	}
	return rules
}

func adaptSecurityGroupRule(resource azure.Resource) network.SecurityGroupRule {
	sourceAddressPrefixes := resource.Properties.GetMapValue("sourceAddressPrefixes").AsStringValuesList("")
	sourceAddressPrefixes = append(sourceAddressPrefixes, resource.Properties.GetMapValue("sourceAddressPrefix").AsStringValue("", resource.Metadata))

	var sourcePortRanges []common.PortRange
	for _, portRange := range resource.Properties.GetMapValue("sourcePortRanges").AsList() {
		rng := parsePortRange(portRange.AsString(), resource.Metadata)
		if rng.Valid() {
			sourcePortRanges = append(sourcePortRanges, rng)
		}
	}
	if rng := parsePortRange(resource.Properties.GetMapValue("sourcePortRange").AsString(), resource.Metadata); rng.Valid() {
		sourcePortRanges = append(sourcePortRanges, rng)
	}

	destinationAddressPrefixes := resource.Properties.GetMapValue("destinationAddressPrefixes").AsStringValuesList("")
	destinationAddressPrefixes = append(destinationAddressPrefixes, resource.Properties.GetMapValue("destinationAddressPrefix").AsStringValue("", resource.Metadata))

	var destinationPortRanges []common.PortRange
	for _, portRange := range resource.Properties.GetMapValue("destinationPortRanges").AsList() {
		rng := parsePortRange(portRange.AsString(), resource.Metadata)
		if rng.Valid() {
			destinationPortRanges = append(destinationPortRanges, rng)
		}
	}
	if rng := parsePortRange(resource.Properties.GetMapValue("destinationPortRange").AsString(), resource.Metadata); rng.Valid() {
		destinationPortRanges = append(destinationPortRanges, rng)
	}

	allow := iacTypes.BoolDefault(false, resource.Metadata)
	if resource.Properties.GetMapValue("access").AsString() == "Allow" {
		allow = iacTypes.Bool(true, resource.Metadata)
	}

	outbound := iacTypes.BoolDefault(false, resource.Metadata)
	if resource.Properties.GetMapValue("direction").AsString() == "Outbound" {
		outbound = iacTypes.Bool(true, resource.Metadata)
	}

	return network.SecurityGroupRule{
		Metadata:             resource.Metadata,
		Outbound:             outbound,
		Allow:                allow,
		SourceAddresses:      sourceAddressPrefixes,
		SourcePorts:          sourcePortRanges,
		DestinationAddresses: destinationAddressPrefixes,
		DestinationPorts:     destinationPortRanges,
		Protocol:             resource.Properties.GetMapValue("protocol").AsStringValue("", resource.Metadata),
	}
}

func adaptNetworkWatcherFlowLogs(deployment azure.Deployment) (flowLogs []network.NetworkWatcherFlowLog) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Network/networkWatchers/flowLogs") {
		flowLogs = append(flowLogs, adaptNetworkWatcherFlowLog(resource))
	}
	return flowLogs
}

func adaptNetworkWatcherFlowLog(resource azure.Resource) network.NetworkWatcherFlowLog {
	return network.NetworkWatcherFlowLog{
		Metadata: resource.Metadata,
		RetentionPolicy: network.RetentionPolicy{
			Metadata: resource.Metadata,
			Enabled:  resource.Properties.GetMapValue("retentionPolicy").GetMapValue("enabled").AsBoolValue(false, resource.Metadata),
			Days:     resource.Properties.GetMapValue("retentionPolicy").GetMapValue("days").AsIntValue(0, resource.Metadata),
		},
	}
}
