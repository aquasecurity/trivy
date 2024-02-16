package keyvault

import (
	"testing"
	"time"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/keyvault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.KeyVault
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_key_vault" "example" {
				name                        = "examplekeyvault"
				enabled_for_disk_encryption = true
				soft_delete_retention_days  = 7
				purge_protection_enabled    = true
			
				network_acls {
					bypass = "AzureServices"
					default_action = "Deny"
				}
			}
`,
			expected: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                iacTypes.NewTestMetadata(),
						EnablePurgeProtection:   iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: iacTypes.Int(7, iacTypes.NewTestMetadata()),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      iacTypes.NewTestMetadata(),
							DefaultAction: iacTypes.String("Deny", iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_key_vault" "example" {
			}
`,
			expected: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                iacTypes.NewTestMetadata(),
						EnablePurgeProtection:   iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: iacTypes.Int(0, iacTypes.NewTestMetadata()),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      iacTypes.NewTestMetadata(),
							DefaultAction: iacTypes.String("", iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSecret(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.Secret
	}{
		{
			name: "defaults",
			terraform: `
			resource "azurerm_key_vault_secret" "example" {
			}
`,
			expected: keyvault.Secret{
				Metadata:    iacTypes.NewTestMetadata(),
				ContentType: iacTypes.String("", iacTypes.NewTestMetadata()),
				ExpiryDate:  iacTypes.Time(time.Time{}, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defined",
			terraform: `
			resource "azurerm_key_vault_secret" "example" {
				content_type = "password"
				expiration_date = "1982-12-31T00:00:00Z"
			}
`,
			expected: keyvault.Secret{
				Metadata:    iacTypes.NewTestMetadata(),
				ContentType: iacTypes.String("password", iacTypes.NewTestMetadata()),
				ExpiryDate: iacTypes.Time(func(timeVal string) time.Time {
					parsed, _ := time.Parse(time.RFC3339, timeVal)
					return parsed
				}("1982-12-31T00:00:00Z"), iacTypes.NewTestMetadata())},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSecret(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptKey(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.Key
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_key_vault_key" "example" {
				name         = "generated-certificate"
				expiration_date = "1982-12-31T00:00:00Z"
			}
`,
			expected: keyvault.Key{
				Metadata: iacTypes.NewTestMetadata(),
				ExpiryDate: iacTypes.Time(func(timeVal string) time.Time {
					parsed, _ := time.Parse(time.RFC3339, timeVal)
					return parsed
				}("1982-12-31T00:00:00Z"), iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_key_vault_key" "example" {
			}
`,
			expected: keyvault.Key{
				Metadata:   iacTypes.NewTestMetadata(),
				ExpiryDate: iacTypes.Time(time.Time{}, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "expiration date refers to the resource",
			terraform: `
terraform {
  required_version = ">=1.3.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=3.0.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">=0.9.0"
    }
  }
}

resource "azurerm_key_vault" "this" {
  name                = "keyvault"
  location            = "us-west"
  resource_group_name = "resource-group"
  tenant_id           = "tenant-id"
  sku_name            = "Standard"
}

resource "time_offset" "expiry" {
  offset_years = 1
  base_rfc3339 = "YYYY-MM-DDTHH:MM:SSZ"
}

resource "azurerm_key_vault_key" "this" {
  name            = "key"
  key_vault_id    = azurerm_key_vault.this.id
  key_type        = "RSA"
  key_size        = 2048
  key_opts        = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
  expiration_date = time_offset.expiry.rfc3339
}
`,
			expected: keyvault.Key{
				Metadata:   iacTypes.NewTestMetadata(),
				ExpiryDate: iacTypes.TimeUnresolvable(iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptKey(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_key_vault" "example" {
		name                        = "examplekeyvault"
		enabled_for_disk_encryption = true
		soft_delete_retention_days  = 7
		purge_protection_enabled    = true
	
		network_acls {
			bypass = "AzureServices"
			default_action = "Deny"
		}
	}

	resource "azurerm_key_vault_key" "example" {
		key_vault_id = azurerm_key_vault.example.id
		name         = "generated-certificate"
		expiration_date = "1982-12-31T00:00:00Z"
	  }

	resource "azurerm_key_vault_secret" "example" {
		key_vault_id = azurerm_key_vault.example.id
		content_type = "password"
		expiration_date = "1982-12-31T00:00:00Z"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Vaults, 1)
	require.Len(t, adapted.Vaults[0].Keys, 1)
	require.Len(t, adapted.Vaults[0].Secrets, 1)

	vault := adapted.Vaults[0]
	key := vault.Keys[0]
	secret := vault.Secrets[0]

	assert.Equal(t, 5, vault.SoftDeleteRetentionDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, vault.SoftDeleteRetentionDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, vault.EnablePurgeProtection.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, vault.EnablePurgeProtection.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, vault.NetworkACLs.DefaultAction.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, vault.NetworkACLs.DefaultAction.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, key.ExpiryDate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, key.ExpiryDate.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, secret.ContentType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, secret.ContentType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, secret.ExpiryDate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, secret.ExpiryDate.GetMetadata().Range().GetEndLine())
}
