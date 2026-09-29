package network

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Network struct {
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
	NetworkInterfaces      []NetworkInterface
}

type SecurityGroup struct {
	Metadata iacTypes.Metadata
	Rules    []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata             iacTypes.Metadata
	Outbound             iacTypes.BoolValue
	Allow                iacTypes.BoolValue
	SourceAddresses      []iacTypes.StringValue
	SourcePorts          []common.PortRange
	DestinationAddresses []iacTypes.StringValue
	DestinationPorts     []common.PortRange
	Protocol             iacTypes.StringValue
}

type NetworkWatcherFlowLog struct {
	Metadata        iacTypes.Metadata
	Enabled         iacTypes.BoolValue
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	Days     iacTypes.IntValue
}

type NetworkInterface struct {
	Metadata           iacTypes.Metadata
	EnableIPForwarding iacTypes.BoolValue
	SecurityGroups     []SecurityGroup

	// Backward compatibility fields.
	// These fields represent the primary IP configuration
	// (or the first one if 'primary' was not explicitly set).
	SubnetID        iacTypes.StringValue
	HasPublicIP     iacTypes.BoolValue
	PublicIPAddress iacTypes.StringValue

	IPConfigurations []IPConfiguration
}

func (ni *NetworkInterface) Setup() {
	for i := range ni.IPConfigurations {
		c := &ni.IPConfigurations[i]
		publicIP := c.PublicIPAddress
		c.HasPublicIP = lo.Ternary(
			publicIP.GetMetadata().IsResolvable(),
			iacTypes.Bool(publicIP.IsNotEmpty(), publicIP.GetMetadata()),
			iacTypes.BoolUnresolvable(c.Metadata),
		)
	}

	if primaryIpConfig, exists := ni.findPrimaryIpConfig(); exists {
		ni.SubnetID = primaryIpConfig.SubnetID
		ni.PublicIPAddress = primaryIpConfig.PublicIPAddress
		ni.HasPublicIP = primaryIpConfig.HasPublicIP
	}
}

func (ni *NetworkInterface) findPrimaryIpConfig() (IPConfiguration, bool) {
	for _, c := range ni.IPConfigurations {
		if c.Primary.Value() {
			return c, true
		}
	}

	if len(ni.IPConfigurations) > 0 {
		return ni.IPConfigurations[0], true
	}
	return IPConfiguration{}, false
}

type IPConfiguration struct {
	Metadata        iacTypes.Metadata
	SubnetID        iacTypes.StringValue
	Primary         iacTypes.BoolValue
	HasPublicIP     iacTypes.BoolValue
	PublicIPAddress iacTypes.StringValue
}
