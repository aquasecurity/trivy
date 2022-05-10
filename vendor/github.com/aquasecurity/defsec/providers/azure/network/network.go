package network

import "github.com/aquasecurity/defsec/parsers/types"

type Network struct {
	types.Metadata
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	types.Metadata
	Rules []SecurityGroupRule
}

type SecurityGroupRule struct {
	types.Metadata
	Outbound             types.BoolValue
	Allow                types.BoolValue
	SourceAddresses      []types.StringValue
	SourcePorts          []PortRange
	DestinationAddresses []types.StringValue
	DestinationPorts     []PortRange
}

type PortRange struct {
	types.Metadata
	Start int
	End   int
}

func (r PortRange) Includes(port int) bool {
	return port >= r.Start && port <= r.End
}

type NetworkWatcherFlowLog struct {
	types.Metadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	types.Metadata
	Enabled types.BoolValue
	Days    types.IntValue
}
