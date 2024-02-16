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
	Start    int
	End      int
}

func (r PortRange) Includes(port int) bool {
	return port >= r.Start && port <= r.End
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
