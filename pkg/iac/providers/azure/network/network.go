package network

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
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
	SourcePorts          []common.PortRange
	DestinationAddresses []iacTypes.StringValue
	DestinationPorts     []common.PortRange
	Protocol             iacTypes.StringValue
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
