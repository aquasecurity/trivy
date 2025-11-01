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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
