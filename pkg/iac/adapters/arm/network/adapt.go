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
	networkInterfaces := []network.NetworkInterface{}

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
		SecurityGroups:     nil,
		SubnetID:           iacTypes.StringDefault("", resource.Metadata),
	}

	ipConfigs := resource.Properties.GetMapValue("ipConfigurations").AsList()
	ni.IPConfigurations = make([]network.IPConfiguration, 0, len(ipConfigs))

	var primaryConfigSet bool

	for _, ipConfig := range ipConfigs {
		if ipConfig.IsNull() {
			continue
		}

		ipConfigMeta := resource.Metadata
		subnetID := ipConfig.GetMapValue("subnet").GetMapValue("id").AsStringValue("", resource.Metadata)
		publicIP := ipConfig.GetMapValue("publicIPAddress")
		hasPublicIP := iacTypes.BoolDefault(false, ipConfigMeta)
		publicIPAddress := iacTypes.StringDefault("", ipConfigMeta)
		primary := ipConfig.GetMapValue("primary").AsBoolValue(false, ipConfigMeta)

		if !publicIP.IsNull() {
			hasPublicIP = iacTypes.Bool(true, ipConfigMeta)
			if publicIPID := publicIP.GetMapValue("id").AsStringValue("", resource.Metadata); publicIPID.Value() != "" {
				publicIPAddress = publicIPID
			}
		}

		ipConfiguration := network.IPConfiguration{
			Metadata:        ipConfigMeta,
			HasPublicIP:     hasPublicIP,
			PublicIPAddress: publicIPAddress,
			SubnetID:        subnetID,
			Primary:         primary,
		}

		ni.IPConfigurations = append(ni.IPConfigurations, ipConfiguration)

		// For backward compatibility, populate the single-value fields with the primary configuration
		// If no primary is set, use the first configuration
		isPrimary := primary.Value() || (len(ni.IPConfigurations) == 1 && !primaryConfigSet && primary.GetMetadata().IsDefault())
		if isPrimary && !primaryConfigSet {
			if subnetID.Value() != "" {
				ni.SubnetID = subnetID
			}
			if hasPublicIP.Value() {
				ni.HasPublicIP = hasPublicIP
				if publicIPAddress.Value() != "" {
					ni.PublicIPAddress = publicIPAddress
				}
			}
			primaryConfigSet = true
		}
	}

	// Note: SecurityGroups are not resolved for ARM templates as related resource search
	// is not yet implemented for ARM (parser cannot evaluate expressions/references)

	return ni
}
