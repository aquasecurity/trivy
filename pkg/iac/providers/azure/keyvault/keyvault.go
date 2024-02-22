package keyvault

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	Metadata                iacTypes.Metadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   iacTypes.BoolValue
	SoftDeleteRetentionDays iacTypes.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	Metadata      iacTypes.Metadata
	DefaultAction iacTypes.StringValue
}

type Key struct {
	Metadata   iacTypes.Metadata
	ExpiryDate iacTypes.TimeValue
}

type Secret struct {
	Metadata    iacTypes.Metadata
	ContentType iacTypes.StringValue
	ExpiryDate  iacTypes.TimeValue
}
