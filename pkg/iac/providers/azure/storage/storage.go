package storage

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Storage struct {
	Accounts []Account
}

type Account struct {
	Metadata                        iacTypes.Metadata
	NetworkRules                    []NetworkRule
	EnforceHTTPS                    iacTypes.BoolValue
	Containers                      []Container
	QueueProperties                 QueueProperties
	MinimumTLSVersion               iacTypes.StringValue
	Queues                          []Queue
	PublicNetworkAccess             iacTypes.BoolValue
	BlobProperties                  BlobProperties
	AccountReplicationType          iacTypes.StringValue
	InfrastructureEncryptionEnabled iacTypes.BoolValue
	CustomerManagedKey              CustomerManagedKey
}

type Queue struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
}

type QueueProperties struct {
	Metadata      iacTypes.Metadata
	EnableLogging iacTypes.BoolValue
	Logging       QueueLogging
}

type QueueLogging struct {
	Metadata            iacTypes.Metadata
	Delete              iacTypes.BoolValue
	Read                iacTypes.BoolValue
	Write               iacTypes.BoolValue
	Version             iacTypes.StringValue
	RetentionPolicyDays iacTypes.IntValue
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

type BlobProperties struct {
	Metadata              iacTypes.Metadata
	DeleteRetentionPolicy DeleteRetentionPolicy
}

type DeleteRetentionPolicy struct {
	Metadata iacTypes.Metadata
	Days     iacTypes.IntValue
}

type CustomerManagedKey struct {
	Metadata               iacTypes.Metadata
	KeyVaultKeyId          iacTypes.StringValue
	UserAssignedIdentityId iacTypes.StringValue
}
