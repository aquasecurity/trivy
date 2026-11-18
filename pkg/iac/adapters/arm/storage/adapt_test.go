package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected storage.Storage
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "properties": {}
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{{
					MinimumTLSVersion: types.StringTest("TLS1_0"),
					EnforceHTTPS:      types.BoolTest(true),
					NetworkRules: []storage.NetworkRule{{
						Bypass:         []types.StringValue{types.StringTest("AzureServices")},
						AllowByDefault: types.BoolTest(true),
					}},
					PublicNetworkAccess:             types.BoolTest(true),
					AccountReplicationType:          types.StringTest(""),
					InfrastructureEncryptionEnabled: types.BoolTest(false),
					BlobProperties: storage.BlobProperties{
						DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
							Days: types.IntTest(0),
						},
					},
					CustomerManagedKey: storage.CustomerManagedKey{
						KeyVaultKeyId:          types.StringTest(""),
						UserAssignedIdentityId: types.StringTest(""),
					},
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": null,
      "properties": {
        "minimumTlsVersion": "TLS1_2",
        "supportsHttpsTrafficOnly": true,
        "publicNetworkAccess": "Disabled",
        "networkAcls": {
          "bypass": "Logging, Metrics",
          "defaultAction": "Allow"
        }
      }
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{{
					MinimumTLSVersion:               types.StringTest("TLS1_2"),
					EnforceHTTPS:                    types.BoolTest(true),
					PublicNetworkAccess:             types.BoolTest(false),
					AccountReplicationType:          types.StringTest(""),
					InfrastructureEncryptionEnabled: types.BoolTest(false),
					NetworkRules: []storage.NetworkRule{{
						Bypass: []types.StringValue{
							types.StringTest("Logging"),
							types.StringTest("Metrics"),
						},
						AllowByDefault: types.BoolTest(true),
					}},
					BlobProperties: storage.BlobProperties{
						DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
							Days: types.IntTest(0),
						},
					},
					CustomerManagedKey: storage.CustomerManagedKey{
						KeyVaultKeyId:          types.StringTest(""),
						UserAssignedIdentityId: types.StringTest(""),
					},
				}},
			},
		},
		{
			name: "containers under the blob service",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "sa",
      "resources": [
        {
          "type": "blobServices",
          "name": "default",
          "resources": [
            {"type": "containers", "name": "private", "properties": {"publicAccess": "None"}},
            {"type": "containers", "name": "blobs", "properties": {"publicAccess": "Blob"}},
            {"type": "Microsoft.Storage/storageAccounts/blobServices/containers", "name": "all", "properties": {"publicAccess": "container"}},
            {"type": "containers", "name": "unset", "properties": {}}
          ]
        }
      ]
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithContainers("off", "blob", "container", "off")},
			},
		},
		{
			name: "containers as children of the account",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "sa",
      "resources": [
        {"type": "blobServices/containers", "name": "default/blobs", "properties": {"publicAccess": "Blob"}}
      ]
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithContainers("blob")},
			},
		},
		{
			name: "top-level containers go to the account they name",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "one"},
    {"type": "Microsoft.Storage/storageAccounts", "name": "two"},
    {
      "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
      "name": "two/default/public",
      "properties": {"publicAccess": "Container"}
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithContainers(), accountWithContainers("container")},
			},
		},
		{
			name: "types match case-insensitively",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "sa",
      "resources": [
        {"type": "BlobServices", "name": "default", "resources": [
          {"type": "Containers", "name": "public", "properties": {"publicAccess": "Container"}}
        ]}
      ]
    },
    {
      "type": "microsoft.storage/storageaccounts/blobservices/containers",
      "name": "SA/default/blobs",
      "properties": {"publicAccess": "Blob"}
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithContainers("container", "blob")},
			},
		},
		{
			name: "top-level container with an expression name goes to the orphan account",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "one"},
    {
      "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
      "name": "[format('{0}/default/public', 'one')]",
      "properties": {"publicAccess": "Container"}
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithContainers(), orphanageWithContainers("container")},
			},
		},
		{
			name: "top-level container goes to the orphan account when the account name is an expression",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "[parameters('name')]"},
    {
      "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
      "name": "one/default/public",
      "properties": {"publicAccess": "Container"}
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithContainers(), orphanageWithContainers("container")},
			},
		},
		{
			name: "queues as children of the queue service and at the top level",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "sa",
      "resources": [
        {"type": "queueServices", "name": "default", "resources": [
          {"type": "queues", "name": "nested"}
        ]}
      ]
    },
    {"type": "Microsoft.Storage/storageAccounts/queueServices/queues", "name": "sa/default/top"},
    {"type": "Microsoft.Storage/storageAccounts/queueServices/queues", "name": "other/default/orphan"}
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{
					accountWithQueues("nested", "top"),
					orphanageWithQueues("orphan"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}

func TestAdaptOrphanageIsUnmanaged(t *testing.T) {
	fsys := testutil.CreateFS(map[string]string{
		"test.json": `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
      "name": "[format('{0}/default/public', parameters('name'))]",
      "properties": {"publicAccess": "Container"}
    }
  ]
}`,
	})
	deployments, err := parser.New(fsys).ParseFS(t.Context(), ".")
	require.NoError(t, err)
	require.Len(t, deployments, 1)

	accounts := Adapt(deployments[0]).Accounts
	require.Len(t, accounts, 1)
	assert.False(t, accounts[0].Metadata.IsManaged())
	require.Len(t, accounts[0].Containers, 1)
	assert.True(t, accounts[0].Containers[0].Metadata.IsManaged())
}

func accountWithContainers(publicAccess ...string) storage.Account {
	account := testAccount()
	account.Containers = testContainers(publicAccess)
	return account
}

func accountWithQueues(names ...string) storage.Account {
	account := testAccount()
	account.Queues = testQueues(names)
	return account
}

func orphanageWithContainers(publicAccess ...string) storage.Account {
	account := testOrphanage()
	account.Containers = testContainers(publicAccess)
	return account
}

func orphanageWithQueues(names ...string) storage.Account {
	account := testOrphanage()
	account.Queues = testQueues(names)
	return account
}

func testContainers(publicAccess []string) []storage.Container {
	var containers []storage.Container
	for _, access := range publicAccess {
		containers = append(containers, storage.Container{PublicAccess: types.StringTest(access)})
	}
	return containers
}

func testQueues(names []string) []storage.Queue {
	var queues []storage.Queue
	for _, name := range names {
		queues = append(queues, storage.Queue{Name: types.StringTest(name)})
	}
	return queues
}

func testOrphanage() storage.Account {
	return storage.Account{
		EnforceHTTPS:                    types.BoolTest(true),
		MinimumTLSVersion:               types.StringTest(""),
		PublicNetworkAccess:             types.BoolTest(false),
		AccountReplicationType:          types.StringTest(""),
		InfrastructureEncryptionEnabled: types.BoolTest(false),
		BlobProperties: storage.BlobProperties{
			DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
				Days: types.IntTest(0),
			},
		},
		CustomerManagedKey: storage.CustomerManagedKey{
			KeyVaultKeyId:          types.StringTest(""),
			UserAssignedIdentityId: types.StringTest(""),
		},
	}
}

func testAccount() storage.Account {
	return storage.Account{
		MinimumTLSVersion: types.StringTest("TLS1_0"),
		EnforceHTTPS:      types.BoolTest(true),
		NetworkRules: []storage.NetworkRule{{
			Bypass:         []types.StringValue{types.StringTest("AzureServices")},
			AllowByDefault: types.BoolTest(true),
		}},
		PublicNetworkAccess:             types.BoolTest(true),
		AccountReplicationType:          types.StringTest(""),
		InfrastructureEncryptionEnabled: types.BoolTest(false),
		BlobProperties: storage.BlobProperties{
			DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
				Days: types.IntTest(0),
			},
		},
		CustomerManagedKey: storage.CustomerManagedKey{
			KeyVaultKeyId:          types.StringTest(""),
			UserAssignedIdentityId: types.StringTest(""),
		},
	}
}
