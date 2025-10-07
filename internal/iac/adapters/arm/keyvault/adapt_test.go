package keyvault

import (
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected keyvault.KeyVault
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.KeyVault/vaults",
      "properties": {}
    },
    {
      "type": "Microsoft.KeyVault/vaults/keys",
      "properties": {}
    },
    {
      "type": "Microsoft.KeyVault/vaults/secrets",
      "properties": {}
    }
  ]
}`,
			expected: keyvault.KeyVault{
				Vaults: []keyvault.Vault{{
					SoftDeleteRetentionDays: types.IntTest(7),
					Keys:                    []keyvault.Key{{}},
					Secrets:                 []keyvault.Secret{{}},
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.KeyVault/vaults",
      "properties": {
        "enablePurgeProtection": true,
        "softDeleteRetentionInDays": 50
      }
    },
    {
      "type": "Microsoft.KeyVault/vaults/keys",
      "properties": {
        "attributes": {
          "exp": 20
        }
      }
    },
    {
      "type": "Microsoft.KeyVault/vaults/secrets",
      "properties": {
        "attributes": {
          "exp": 20
        },
        "contentType": "text/plain"
      }
    }
  ]
}`,
			expected: keyvault.KeyVault{
				Vaults: []keyvault.Vault{{
					EnablePurgeProtection:   types.BoolTest(true),
					SoftDeleteRetentionDays: types.IntTest(50),
					Keys: []keyvault.Key{{
						ExpiryDate: types.Time(time.Unix(20, 0), types.NewTestMetadata()),
					}},
					Secrets: []keyvault.Secret{{
						ExpiryDate:  types.Time(time.Unix(20, 0), types.NewTestMetadata()),
						ContentType: types.StringTest("text/plain"),
					}},
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
