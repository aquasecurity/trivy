package keyvault

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	types.Metadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   types.BoolValue
	SoftDeleteRetentionDays types.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	types.Metadata
	DefaultAction types.StringValue
}

type Key struct {
	types.Metadata
	ExpiryDate types.TimeValue
}

type Secret struct {
	types.Metadata
	ContentType types.StringValue
	ExpiryDate  types.TimeValue
}
