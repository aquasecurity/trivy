package storage

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Storage struct {
	Accounts []Account
}

type Account struct {
	Metadata          defsecTypes.Metadata
	NetworkRules      []NetworkRule
	EnforceHTTPS      defsecTypes.BoolValue
	Containers        []Container
	QueueProperties   QueueProperties
	MinimumTLSVersion defsecTypes.StringValue
	Queues            []Queue
}

type Queue struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
}

type QueueProperties struct {
	Metadata      defsecTypes.Metadata
	EnableLogging defsecTypes.BoolValue
}

type NetworkRule struct {
	Metadata       defsecTypes.Metadata
	Bypass         []defsecTypes.StringValue
	AllowByDefault defsecTypes.BoolValue
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	Metadata     defsecTypes.Metadata
	PublicAccess defsecTypes.StringValue
}
