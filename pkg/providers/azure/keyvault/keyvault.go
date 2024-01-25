package keyvault

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	Metadata                defsecTypes.MisconfigMetadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   defsecTypes.BoolValue
	SoftDeleteRetentionDays defsecTypes.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	Metadata      defsecTypes.MisconfigMetadata
	DefaultAction defsecTypes.StringValue
}

type Key struct {
	Metadata   defsecTypes.MisconfigMetadata
	ExpiryDate defsecTypes.TimeValue
}

type Secret struct {
	Metadata    defsecTypes.MisconfigMetadata
	ContentType defsecTypes.StringValue
	ExpiryDate  defsecTypes.TimeValue
}
