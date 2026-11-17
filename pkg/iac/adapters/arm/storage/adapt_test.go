package storage

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
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
				Accounts: []storage.Account{accountWithContainers("off", "blob", "off", "container")},
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
			name: "top-level container with an expression name goes to every account",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "one"},
    {"type": "Microsoft.Storage/storageAccounts", "name": "two"},
    {
      "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
      "name": "[format('{0}/default/public', 'one')]",
      "properties": {"publicAccess": "Container"}
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithContainers("container"), accountWithContainers("container")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}

func accountWithContainers(publicAccess ...string) storage.Account {
	var containers []storage.Container
	for _, access := range publicAccess {
		containers = append(containers, storage.Container{PublicAccess: types.StringTest(access)})
	}
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
		Containers:                      containers,
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
