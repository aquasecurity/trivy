package network

import (
	"strconv"
	"strings"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

func Adapt(deployment azure.Deployment) network.Network {
	return network.Network{
		SecurityGroups:         xslices.ZeroToNil(adaptSecurityGroups(deployment)),
		NetworkWatcherFlowLogs: xslices.ZeroToNil(adaptNetworkWatcherFlowLogs(deployment)),
	}
}

func adaptSecurityGroups(deployment azure.Deployment) []network.SecurityGroup {
	return lo.Map(deployment.GetResourcesByType("Microsoft.Network/networkSecurityGroups"),
		func(r azure.Resource, _ int) network.SecurityGroup { return adaptSecurityGroup(r) },
	)
}

func adaptSecurityGroup(resource azure.Resource) network.SecurityGroup {
	return network.SecurityGroup{
		Metadata: resource.Metadata,
		Rules:    xslices.ZeroToNil(adaptSecurityGroupRules(resource)),
	}
}

func adaptSecurityGroupRules(resource azure.Resource) []network.SecurityGroupRule {
	// TODO: handle Microsoft.Network/networkSecurityGroups/securityRules
	// TODO: handle Microsoft.Network -> networkSecurityGroups -> securityRules

	var secRules []network.SecurityGroupRule
	for _, secRulesProp := range resource.Properties.GetMapValue("securityRules").AsList() {
		if props := secRulesProp.GetMapValue("properties"); !props.IsNull() {
			secRules = append(secRules, adaptSecurityGroupRule(props, secRulesProp.GetMetadata()))
		}
	}

	for _, secRuleRes := range resource.GetResourcesByType("securityRules") {
		secRules = append(secRules, adaptSecurityGroupRule(secRuleRes.Properties, secRuleRes.Metadata))
	}
	return secRules
}

func adaptSecurityGroupRule(props azure.Value, parentMeta iacTypes.Metadata) network.SecurityGroupRule {
	// TODO: introduce AddressRange
	sourcePrefixes := append(
		props.GetMapValue("sourceAddressPrefixes").AsList(),
		props.GetMapValue("sourceAddressPrefix"),
	)
	sourceAddressPrefixes := lo.FilterMap(sourcePrefixes, func(v azure.Value, _ int) (iacTypes.StringValue, bool) {
		return v.AsStringValue("", parentMeta), !v.IsNull()
	})

	sourcePorts := append(
		props.GetMapValue("sourcePortRanges").AsList(),
		props.GetMapValue("sourcePortRange"),
	)
	sourcePortRanges := lo.FilterMap(sourcePorts, func(v azure.Value, _ int) (network.PortRange, bool) {
		return expandRange(v.AsString(), v.GetMetadata()), !v.IsNull()
	})

	destinationPrefixes := append(
		props.GetMapValue("destinationAddressPrefixes").AsList(),
		props.GetMapValue("destinationAddressPrefix"),
	)
	destinationAddressPrefixes := lo.FilterMap(destinationPrefixes, func(v azure.Value, _ int) (iacTypes.StringValue, bool) {
		return v.AsStringValue("", parentMeta), !v.IsNull()
	})

	destinationPorts := append(
		props.GetMapValue("destinationPortRanges").AsList(),
		props.GetMapValue("destinationPortRange"),
	)
	destinationPortRanges := lo.FilterMap(destinationPorts, func(v azure.Value, _ int) (network.PortRange, bool) {
		return expandRange(v.AsString(), v.GetMetadata()), !v.IsNull()
	})

	allow := iacTypes.BoolDefault(false, parentMeta)
	if access := props.GetMapValue("access"); !access.IsNull() {
		allow = iacTypes.Bool(access.EqualTo("Allow"), access.GetMetadata())
	}

	outbound := iacTypes.Bool(props.GetMapValue("direction").AsString() == "Outbound", parentMeta)

	return network.SecurityGroupRule{
		Metadata:             props.Metadata,
		Outbound:             outbound,
		Allow:                allow,
		SourceAddresses:      sourceAddressPrefixes,
		SourcePorts:          sourcePortRanges,
		DestinationAddresses: destinationAddressPrefixes,
		DestinationPorts:     destinationPortRanges,
		Protocol:             props.GetMapValue("protocol").AsStringValue("", parentMeta),
	}
}

func adaptNetworkWatcherFlowLogs(deployment azure.Deployment) (flowLogs []network.NetworkWatcherFlowLog) {
	return lo.Map(deployment.GetResourcesByType("Microsoft.Network/networkWatchers/flowLogs"),
		func(r azure.Resource, _ int) network.NetworkWatcherFlowLog { return adaptNetworkWatcherFlowLog(r) },
	)
}

func adaptNetworkWatcherFlowLog(resource azure.Resource) network.NetworkWatcherFlowLog {
	return network.NetworkWatcherFlowLog{
		Metadata: resource.Metadata,
		RetentionPolicy: network.RetentionPolicy{
			Metadata: resource.Metadata,
			Enabled: resource.Properties.GetMapValue("retentionPolicy").GetMapValue("enabled").
				AsBoolValue(false, resource.Metadata),
			Days: resource.Properties.GetMapValue("retentionPolicy").GetMapValue("days").
				AsIntValue(0, resource.Metadata),
		},
	}
}

func expandRange(r string, m iacTypes.Metadata) network.PortRange {
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
		Start:    iacTypes.Int(start, m),
		End:      iacTypes.Int(end, m),
	}
}
