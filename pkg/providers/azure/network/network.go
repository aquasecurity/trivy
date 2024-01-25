package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Network struct {
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	Metadata defsecTypes.MisconfigMetadata
	Rules    []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata             defsecTypes.MisconfigMetadata
	Outbound             defsecTypes.BoolValue
	Allow                defsecTypes.BoolValue
	SourceAddresses      []defsecTypes.StringValue
	SourcePorts          []PortRange
	DestinationAddresses []defsecTypes.StringValue
	DestinationPorts     []PortRange
	Protocol             defsecTypes.StringValue
}

type PortRange struct {
	Metadata defsecTypes.MisconfigMetadata
	Start    int
	End      int
}

func (r PortRange) Includes(port int) bool {
	return port >= r.Start && port <= r.End
}

type NetworkWatcherFlowLog struct {
	Metadata        defsecTypes.MisconfigMetadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
	Days     defsecTypes.IntValue
}
