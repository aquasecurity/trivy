package storage

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdaptDiagnosticLogging(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected storage.Storage
	}{
		{
			name: "diagnostic setting with literal scope logs blob requests",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "sa"},
    {
      "type": "Microsoft.Insights/diagnosticSettings",
      "name": "blob-logs",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/sa/blobServices/default",
      "properties": {
        "logs": [{"category": "StorageRead", "enabled": true}]
      }
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{diagnosticTestAccount(true, false, false, false)},
			},
		},
		{
			name: "diagnostic setting with resourceId scope logs queue requests",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "sa"},
    {
      "type": "Microsoft.Insights/diagnosticSettings",
      "name": "queue-logs",
      "scope": "[resourceId('Microsoft.Storage/storageAccounts/queueServices', 'sa', 'default')]",
      "properties": {
        "logs": [{"categoryGroup": "allLogs"}]
      }
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{diagnosticTestAccount(false, false, true, false)},
			},
		},
		{
			name: "diagnostic setting nested under a service logs file requests",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "sa",
      "resources": [
        {
          "type": "fileServices",
          "name": "default",
          "resources": [
            {
              "type": "Microsoft.Insights/diagnosticSettings",
              "name": "file-logs",
              "properties": {
                "logs": [{"category": "StorageWrite"}]
              }
            }
          ]
        }
      ]
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{diagnosticTestAccount(false, true, false, false)},
			},
		},
		{
			name: "diagnostic setting targeting the account does not count",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "sa"},
    {
      "type": "Microsoft.Insights/diagnosticSettings",
      "name": "account-logs",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/sa",
      "properties": {
        "logs": [{"category": "StorageWrite"}]
      }
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{diagnosticTestAccount(false, false, false, false)},
			},
		},
		{
			name: "diagnostic setting targeting another account does not count",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "one"},
    {"type": "Microsoft.Storage/storageAccounts", "name": "other"},
    {
      "type": "Microsoft.Insights/diagnosticSettings",
      "name": "other-logs",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/other/blobServices/default",
      "properties": {
        "logs": [{"category": "StorageRead"}]
      }
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{
					diagnosticTestAccount(false, false, false, false),
					diagnosticTestAccount(true, false, false, false),
				},
			},
		},
		{
			name: "disabled log entry does not count",
			source: `{
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "sa"},
    {
      "type": "Microsoft.Insights/diagnosticSettings",
      "name": "blob-logs",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/sa/blobServices/default",
      "properties": {
        "logs": [{"category": "StorageRead", "enabled": false}]
      }
    }
  ]
}`,
			expected: storage.Storage{
				Accounts: []storage.Account{diagnosticTestAccount(false, false, false, false)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}

func diagnosticTestAccount(blob, file, queue, table bool) storage.Account {
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
		DiagnosticLogging: storage.DiagnosticLogging{
			Blob:  types.BoolTest(blob),
			File:  types.BoolTest(file),
			Queue: types.BoolTest(queue),
			Table: types.BoolTest(table),
		},
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
