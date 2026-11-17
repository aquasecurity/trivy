package network

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const securityRuleType = "Microsoft.Network/networkSecurityGroups/securityRules"

func parsePortRange(input string, meta iacTypes.Metadata) common.PortRange {
	return common.ParsePortRange(input, meta, common.WithWildcard())
}

func Adapt(deployment azure.Deployment) network.Network {
	return network.Network{
		SecurityGroups:         adaptSecurityGroups(deployment),
		NetworkWatcherFlowLogs: adaptNetworkWatcherFlowLogs(deployment),
		NetworkInterfaces:      adaptNetworkInterfaces(deployment),
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
		Rules:    adaptSecurityGroupRules(resource, deployment),
	}
}

// adaptSecurityGroupRules collects the rules of a network security group from
// all the places an ARM template can declare them: the securityRules property,
// child resources, and top-level securityRules resources.
func adaptSecurityGroupRules(group azure.Resource, deployment azure.Deployment) (rules []network.SecurityGroupRule) {
	for _, rule := range group.Properties.GetMapValue("securityRules").AsList() {
		rules = append(rules, adaptSecurityGroupRule(rule.GetMapValue("properties"), rule.GetMetadata()))
	}
	for _, typ := range []string{"securityRules", securityRuleType} {
		for _, resource := range group.GetResourcesByType(typ) {
			rules = append(rules, adaptSecurityGroupRule(resource.Properties, resource.Metadata))
		}
	}
	for _, resource := range deployment.GetResourcesByType(securityRuleType) {
		if belongsToGroup(resource, group) {
			rules = append(rules, adaptSecurityGroupRule(resource.Properties, resource.Metadata))
		}
	}
	return rules
}

// belongsToGroup reports whether a top-level security rule belongs to group.
// The name of such a rule is "<group name>/<rule name>". When either name is an
// expression, which the parser does not evaluate, the rule is kept.
func belongsToGroup(rule, group azure.Resource) bool {
	ruleName, groupName := rule.Name.AsString(), group.Name.AsString()
	if ruleName == "" || groupName == "" {
		return true
	}
	parent, _, found := strings.Cut(ruleName, "/")
	return !found || strings.EqualFold(parent, groupName)
}

func adaptSecurityGroupRule(properties azure.Value, metadata iacTypes.Metadata) network.SecurityGroupRule {
	sourceAddressPrefixes := properties.GetMapValue("sourceAddressPrefixes").AsStringValuesList("")
	if prefix := properties.GetMapValue("sourceAddressPrefix").AsStringValue("", metadata); prefix.IsNotEmpty() {
		sourceAddressPrefixes = append(sourceAddressPrefixes, prefix)
	}

	var sourcePortRanges []common.PortRange
	for _, portRange := range properties.GetMapValue("sourcePortRanges").AsList() {
		rng := parsePortRange(portRange.AsString(), metadata)
		if rng.Valid() {
			sourcePortRanges = append(sourcePortRanges, rng)
		}
	}
	if rng := parsePortRange(properties.GetMapValue("sourcePortRange").AsString(), metadata); rng.Valid() {
		sourcePortRanges = append(sourcePortRanges, rng)
	}

	destinationAddressPrefixes := properties.GetMapValue("destinationAddressPrefixes").AsStringValuesList("")
	if prefix := properties.GetMapValue("destinationAddressPrefix").AsStringValue("", metadata); prefix.IsNotEmpty() {
		destinationAddressPrefixes = append(destinationAddressPrefixes, prefix)
	}

	var destinationPortRanges []common.PortRange
	for _, portRange := range properties.GetMapValue("destinationPortRanges").AsList() {
		rng := parsePortRange(portRange.AsString(), metadata)
		if rng.Valid() {
			destinationPortRanges = append(destinationPortRanges, rng)
		}
	}
	if rng := parsePortRange(properties.GetMapValue("destinationPortRange").AsString(), metadata); rng.Valid() {
		destinationPortRanges = append(destinationPortRanges, rng)
	}

	allow := iacTypes.BoolDefault(false, metadata)
	if properties.GetMapValue("access").AsString() == "Allow" {
		allow = iacTypes.Bool(true, metadata)
	}

	outbound := iacTypes.BoolDefault(false, metadata)
	if properties.GetMapValue("direction").AsString() == "Outbound" {
		outbound = iacTypes.Bool(true, metadata)
	}

	return network.SecurityGroupRule{
		Metadata:             metadata,
		Outbound:             outbound,
		Allow:                allow,
		SourceAddresses:      sourceAddressPrefixes,
		SourcePorts:          sourcePortRanges,
		DestinationAddresses: destinationAddressPrefixes,
		DestinationPorts:     destinationPortRanges,
		Protocol:             properties.GetMapValue("protocol").AsStringValue("", metadata),
	}
}

func adaptNetworkWatcherFlowLogs(deployment azure.Deployment) (flowLogs []network.NetworkWatcherFlowLog) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Network/networkWatchers/flowLogs") {
		flowLogs = append(flowLogs, adaptNetworkWatcherFlowLog(resource))
	}
	return flowLogs
}

func adaptNetworkWatcherFlowLog(resource azure.Resource) network.NetworkWatcherFlowLog {
	enabled := resource.Properties.GetMapValue("enabled").AsBoolValue(false, resource.Metadata)
	retentionPolicy := resource.Properties.GetMapValue("retentionPolicy")

	return network.NetworkWatcherFlowLog{
		Metadata: resource.Metadata,
		Enabled:  enabled,
		RetentionPolicy: network.RetentionPolicy{
			Metadata: resource.Metadata,
			Enabled:  retentionPolicy.GetMapValue("enabled").AsBoolValue(false, resource.Metadata),
			Days:     retentionPolicy.GetMapValue("days").AsIntValue(0, resource.Metadata),
		},
	}
}

func adaptNetworkInterfaces(deployment azure.Deployment) []network.NetworkInterface {
	var networkInterfaces []network.NetworkInterface
	for _, resource := range deployment.GetResourcesByType("Microsoft.Network/networkInterfaces") {
		networkInterfaces = append(networkInterfaces, adaptNetworkInterface(resource, deployment))
	}
	return networkInterfaces
}

func adaptNetworkInterface(resource azure.Resource, _ azure.Deployment) network.NetworkInterface {
	ni := network.NetworkInterface{
		Metadata:           resource.Metadata,
		EnableIPForwarding: resource.Properties.GetMapValue("enableIPForwarding").AsBoolValue(false, resource.Metadata),
		HasPublicIP:        iacTypes.BoolDefault(false, resource.Metadata),
		PublicIPAddress:    iacTypes.StringDefault("", resource.Metadata),
		SubnetID:           iacTypes.StringDefault("", resource.Metadata),
	}

	ipConfigs := resource.Properties.GetMapValue("ipConfigurations").AsList()
	ni.IPConfigurations = make([]network.IPConfiguration, 0, len(ipConfigs))

	for _, ipConfig := range ipConfigs {
		if ipConfig.IsNull() {
			continue
		}
		ipConfigProps := ipConfig.GetMapValue("properties")
		ni.IPConfigurations = append(ni.IPConfigurations, network.IPConfiguration{
			Metadata: resource.Metadata,
			PublicIPAddress: ipConfigProps.GetMapValue("publicIPAddress").
				GetMapValue("id").AsStringValue("", resource.Metadata),
			SubnetID: ipConfigProps.GetMapValue("subnet").
				GetMapValue("id").AsStringValue("", resource.Metadata),
			Primary: ipConfigProps.GetMapValue("primary").AsBoolValue(false, resource.Metadata),
		})
	}
	ni.Setup()

	// Note: SecurityGroups are not resolved for ARM templates as related resource search
	// is not yet implemented for ARM (parser cannot evaluate expressions/references)
	return ni
}
