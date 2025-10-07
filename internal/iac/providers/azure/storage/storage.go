package storage

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Storage struct {
	Accounts []Account
}

type Account struct {
	Metadata            iacTypes.Metadata
	NetworkRules        []NetworkRule
	EnforceHTTPS        iacTypes.BoolValue
	Containers          []Container
	QueueProperties     QueueProperties
	MinimumTLSVersion   iacTypes.StringValue
	Queues              []Queue
	PublicNetworkAccess iacTypes.BoolValue
}

type Queue struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
}

type QueueProperties struct {
	Metadata      iacTypes.Metadata
	EnableLogging iacTypes.BoolValue
}

type NetworkRule struct {
	Metadata       iacTypes.Metadata
	Bypass         []iacTypes.StringValue
	AllowByDefault iacTypes.BoolValue
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	Metadata     iacTypes.Metadata
	PublicAccess iacTypes.StringValue
}
