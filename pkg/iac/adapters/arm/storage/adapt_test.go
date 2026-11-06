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
			name: "nested blob service with soft delete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "properties": {},
      "resources": [
        {
          "type": "blobServices",
          "name": "default",
          "properties": {
            "deleteRetentionPolicy": {
              "enabled": true,
              "days": 7
            }
          }
        }
      ]
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithBlobRetentionDays(7)},
			},
		},
		{
			name: "nested blob service with full resource type",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "properties": {},
      "resources": [
        {
          "type": "Microsoft.Storage/storageAccounts/blobServices",
          "name": "default",
          "properties": {
            "deleteRetentionPolicy": {
              "enabled": true,
              "days": 14
            }
          }
        }
      ]
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithBlobRetentionDays(14)},
			},
		},
		{
			name: "nested blob service with soft delete disabled",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "properties": {},
      "resources": [
        {
          "type": "blobServices",
          "name": "default",
          "properties": {
            "deleteRetentionPolicy": {
              "enabled": false,
              "days": 7
            }
          }
        }
      ]
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithBlobRetentionDays(0)},
			},
		},
		{
			name: "nested blob service without retention policy",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "properties": {},
      "resources": [
        {
          "type": "blobServices",
          "name": "default",
          "properties": {}
        }
      ]
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{accountWithBlobRetentionDays(0)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}

func accountWithBlobRetentionDays(days int) storage.Account {
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
				Days: types.IntTest(days),
			},
		},
		CustomerManagedKey: storage.CustomerManagedKey{
			KeyVaultKeyId:          types.StringTest(""),
			UserAssignedIdentityId: types.StringTest(""),
		},
	}
}
