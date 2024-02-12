package keyvault

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	Metadata                defsecTypes.Metadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   defsecTypes.BoolValue
	SoftDeleteRetentionDays defsecTypes.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	Metadata      defsecTypes.Metadata
	DefaultAction defsecTypes.StringValue
}

type Key struct {
	Metadata   defsecTypes.Metadata
	ExpiryDate defsecTypes.TimeValue
}

type Secret struct {
	Metadata    defsecTypes.Metadata
	ContentType defsecTypes.StringValue
	ExpiryDate  defsecTypes.TimeValue
}
