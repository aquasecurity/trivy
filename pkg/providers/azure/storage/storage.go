package storage

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Storage struct {
	Accounts []Account
}

type Account struct {
	Metadata          defsecTypes.MisconfigMetadata
	NetworkRules      []NetworkRule
	EnforceHTTPS      defsecTypes.BoolValue
	Containers        []Container
	QueueProperties   QueueProperties
	MinimumTLSVersion defsecTypes.StringValue
	Queues            []Queue
}

type Queue struct {
	Metadata defsecTypes.MisconfigMetadata
	Name     defsecTypes.StringValue
}

type QueueProperties struct {
	Metadata      defsecTypes.MisconfigMetadata
	EnableLogging defsecTypes.BoolValue
}

type NetworkRule struct {
	Metadata       defsecTypes.MisconfigMetadata
	Bypass         []defsecTypes.StringValue
	AllowByDefault defsecTypes.BoolValue
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	Metadata     defsecTypes.MisconfigMetadata
	PublicAccess defsecTypes.StringValue
}
