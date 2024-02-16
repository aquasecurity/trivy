package storage

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  storage.Storage
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_resource_group" "example" {
				name     = "example"
			  }

			resource "azurerm_storage_account" "example" {
				name                     = "storageaccountname"
				resource_group_name      = azurerm_resource_group.example.name

				network_rules {
					default_action             = "Deny"
					bypass                     = ["Metrics", "AzureServices"]
				  }

				enable_https_traffic_only = true
				queue_properties  {
					logging {
						delete                = true
						read                  = true
						write                 = true
						version               = "1.0"
						retention_policy_days = 10
					}
				  }
				min_tls_version          = "TLS1_2"
			  }

			  resource "azurerm_storage_account_network_rules" "test" {
				resource_group_name      = azurerm_resource_group.example.name
				storage_account_name = azurerm_storage_account.example.name
			  
				default_action             = "Allow"
				bypass                     = ["Metrics"]
			  }

			  resource "azurerm_storage_container" "example" {
				storage_account_name = azurerm_storage_account.example.name
				resource_group_name      = azurerm_resource_group.example.name
				container_access_type = "blob"
			}
`,
			expected: storage.Storage{
				Accounts: []storage.Account{

					{
						Metadata:          iacTypes.NewTestMetadata(),
						EnforceHTTPS:      iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						MinimumTLSVersion: iacTypes.String("TLS1_2", iacTypes.NewTestMetadata()),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Bypass: []iacTypes.StringValue{
									iacTypes.String("Metrics", iacTypes.NewTestMetadata()),
									iacTypes.String("AzureServices", iacTypes.NewTestMetadata()),
								},
								AllowByDefault: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							},
							{
								Metadata: iacTypes.NewTestMetadata(),
								Bypass: []iacTypes.StringValue{
									iacTypes.String("Metrics", iacTypes.NewTestMetadata()),
								},
								AllowByDefault: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							},
						},
						QueueProperties: storage.QueueProperties{
							Metadata:      iacTypes.NewTestMetadata(),
							EnableLogging: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
						Containers: []storage.Container{
							{
								Metadata:     iacTypes.NewTestMetadata(),
								PublicAccess: iacTypes.String("blob", iacTypes.NewTestMetadata()),
							},
						},
					},
					{
						Metadata:     iacTypes.NewUnmanagedMetadata(),
						EnforceHTTPS: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
						QueueProperties: storage.QueueProperties{
							Metadata:      iacTypes.NewUnmanagedMetadata(),
							EnableLogging: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
						},
						MinimumTLSVersion: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
					},
				},
			},
		},
		{
			name: "orphans",
			terraform: `
			resource "azurerm_storage_account_network_rules" "test" {
				default_action             = "Allow"
				bypass                     = ["Metrics"]
			  }

			  resource "azurerm_storage_container" "example" {
				container_access_type = "blob"
			}
`,
			expected: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:     iacTypes.NewUnmanagedMetadata(),
						EnforceHTTPS: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Bypass: []iacTypes.StringValue{
									iacTypes.String("Metrics", iacTypes.NewTestMetadata()),
								},
								AllowByDefault: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							},
						},
						QueueProperties: storage.QueueProperties{
							Metadata:      iacTypes.NewUnmanagedMetadata(),
							EnableLogging: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
						},
						MinimumTLSVersion: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
						Containers: []storage.Container{
							{
								Metadata:     iacTypes.NewTestMetadata(),
								PublicAccess: iacTypes.String("blob", iacTypes.NewTestMetadata()),
							},
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

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_resource_group" "example" {
		name     = "example"
		location = "West Europe"
	  }

	resource "azurerm_storage_account" "example" {
		resource_group_name      = azurerm_resource_group.example.name

		enable_https_traffic_only = true
		min_tls_version          = "TLS1_2"

		queue_properties  {
			logging {
				delete                = true
				read                  = true
				write                 = true
				version               = "1.0"
				retention_policy_days = 10
			}
		  }

		network_rules {
			default_action             = "Deny"
			bypass                     = ["Metrics", "AzureServices"]
		  }
	  }

	  resource "azurerm_storage_account_network_rules" "test" {
		resource_group_name      = azurerm_resource_group.example.name
		storage_account_name = azurerm_storage_account.example.name
	  
		default_action             = "Allow"
		bypass                     = ["Metrics"]
	  }

	  resource "azurerm_storage_container" "example" {
		storage_account_name = azurerm_storage_account.example.name
		resource_group_name      = azurerm_resource_group.example.name
		container_access_type = "blob"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Accounts, 2) //+orphans holder
	account := adapted.Accounts[0]

	assert.Equal(t, 7, account.Metadata.Range().GetStartLine())
	assert.Equal(t, 27, account.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, account.EnforceHTTPS.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, account.EnforceHTTPS.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, account.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, account.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, account.QueueProperties.Metadata.Range().GetStartLine())
	assert.Equal(t, 21, account.QueueProperties.Metadata.Range().GetEndLine())

	assert.Equal(t, 14, account.QueueProperties.EnableLogging.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, account.QueueProperties.EnableLogging.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, account.NetworkRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 26, account.NetworkRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 24, account.NetworkRules[0].AllowByDefault.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, account.NetworkRules[0].AllowByDefault.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 25, account.NetworkRules[0].Bypass[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, account.NetworkRules[0].Bypass[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 29, account.NetworkRules[1].Metadata.Range().GetStartLine())
	assert.Equal(t, 35, account.NetworkRules[1].Metadata.Range().GetEndLine())

	assert.Equal(t, 33, account.NetworkRules[1].AllowByDefault.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 33, account.NetworkRules[1].AllowByDefault.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 34, account.NetworkRules[1].Bypass[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, account.NetworkRules[1].Bypass[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 37, account.Containers[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 41, account.Containers[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 40, account.Containers[0].PublicAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 40, account.Containers[0].PublicAccess.GetMetadata().Range().GetEndLine())

}
