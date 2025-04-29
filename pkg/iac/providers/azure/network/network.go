package network

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Network struct {
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
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
	SourcePorts          []PortRange
	DestinationAddresses []iacTypes.StringValue
	DestinationPorts     []PortRange
	Protocol             iacTypes.StringValue
}

type PortRange struct {
	Metadata iacTypes.Metadata
	Start    iacTypes.IntValue
	End      iacTypes.IntValue
}

type NetworkWatcherFlowLog struct {
	Metadata        iacTypes.Metadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	Days     iacTypes.IntValue
}
