package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  storage.Storage
	}{
		{
			name:      "default",
			terraform: `resource "azurerm_storage_account" "example" {}`,
			expected: storage.Storage{
				Accounts: []storage.Account{
					{
						PublicNetworkAccess: iacTypes.BoolTest(true),
						MinimumTLSVersion:   iacTypes.StringTest(minimumTlsVersionOneTwo),
						EnforceHTTPS:        iacTypes.BoolTest(true),
						BlobProperties: storage.BlobProperties{
							DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
								Days: iacTypes.IntTest(7),
							},
						},
						CustomerManagedKey: storage.CustomerManagedKey{},
					},
					{
						BlobProperties: storage.BlobProperties{
							DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
								Days: iacTypes.IntTest(7),
							},
						},
					},
				},
			},
		},
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
				public_network_access_enabled = false
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
						EnforceHTTPS:      iacTypes.BoolTest(true),
						MinimumTLSVersion: iacTypes.StringTest("TLS1_2"),
						NetworkRules: []storage.NetworkRule{
							{
								Bypass: []iacTypes.StringValue{
									iacTypes.StringTest("Metrics"),
									iacTypes.StringTest("AzureServices"),
								},
							},
							{
								Bypass: []iacTypes.StringValue{
									iacTypes.StringTest("Metrics"),
								},
								AllowByDefault: iacTypes.BoolTest(true),
							},
						},
						QueueProperties: storage.QueueProperties{
							EnableLogging: iacTypes.BoolTest(true),
							Logging: storage.QueueLogging{
								Delete:              iacTypes.BoolTest(true),
								Read:                iacTypes.BoolTest(true),
								Write:               iacTypes.BoolTest(true),
								Version:             iacTypes.StringTest("1.0"),
								RetentionPolicyDays: iacTypes.IntTest(10),
							},
						},
						BlobProperties: storage.BlobProperties{
							DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
								Days: iacTypes.IntTest(7),
							},
						},
						CustomerManagedKey: storage.CustomerManagedKey{},
						Containers: []storage.Container{
							{
								PublicAccess: iacTypes.StringTest("blob"),
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
						MinimumTLSVersion:               iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
						AccountReplicationType:          iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
						InfrastructureEncryptionEnabled: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
						BlobProperties: storage.BlobProperties{
							DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
								Days: iacTypes.IntDefault(7, iacTypes.NewUnmanagedMetadata()),
							},
						},
						CustomerManagedKey: storage.CustomerManagedKey{
							KeyVaultKeyId:          iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
							UserAssignedIdentityId: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
						},
					},
				},
			},
		},
		{
			name: "references via storage_account_id",
			terraform: `
    		resource "azurerm_resource_group" "example" {
        	  name = "example"
    		}

    		resource "azurerm_storage_account" "example" {
        	  name                = "storageaccountname"
       		  resource_group_name = azurerm_resource_group.example.name
    		}

    		resource "azurerm_storage_account_network_rules" "example" {
        	  storage_account_id = azurerm_storage_account.example.id
        	  default_action     = "Deny"
    		}

    		resource "azurerm_storage_container" "example" {
    	      storage_account_id     = azurerm_storage_account.example.id
       		  container_access_type = "blob"
    		}

    		resource "azurerm_storage_queue" "example" {
			  storage_account_id = azurerm_storage_account.example.id
        	  name               = "queue1"
    		}
`,
			expected: storage.Storage{
				Accounts: []storage.Account{
					{
						EnforceHTTPS:        iacTypes.BoolTest(true),
						MinimumTLSVersion:   iacTypes.StringTest(minimumTlsVersionOneTwo),
						PublicNetworkAccess: iacTypes.BoolTest(true),
						BlobProperties: storage.BlobProperties{
							DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
								Days: iacTypes.IntTest(7),
							},
						},
						NetworkRules: []storage.NetworkRule{
							{
								AllowByDefault: iacTypes.BoolTest(false),
							},
						},
						Containers: []storage.Container{
							{
								PublicAccess: iacTypes.StringTest("blob"),
							},
						},
						Queues: []storage.Queue{
							{
								Name: iacTypes.StringTest("queue1"),
							},
						},
					},
					// orphan account holder
					{
						BlobProperties: storage.BlobProperties{
							DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
								Days: iacTypes.IntTest(7),
							},
						},
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
								Bypass: []iacTypes.StringValue{
									iacTypes.StringTest("Metrics"),
								},
								AllowByDefault: iacTypes.BoolTest(true),
							},
						},
						QueueProperties: storage.QueueProperties{
							Metadata:      iacTypes.NewUnmanagedMetadata(),
							EnableLogging: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
						},
						MinimumTLSVersion:               iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
						AccountReplicationType:          iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
						InfrastructureEncryptionEnabled: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
						BlobProperties: storage.BlobProperties{
							DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
								Days: iacTypes.IntDefault(7, iacTypes.NewUnmanagedMetadata()),
							},
						},
						CustomerManagedKey: storage.CustomerManagedKey{
							KeyVaultKeyId:          iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
							UserAssignedIdentityId: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
						},
						Containers: []storage.Container{
							{
								PublicAccess: iacTypes.StringTest("blob"),
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
