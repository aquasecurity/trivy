package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_AdaptStorageDefaults(t *testing.T) {

	input := azure.Deployment{
		Resources: []azure.Resource{
			{
				Type:       azure.NewValue("Microsoft.Storage/storageAccounts", types.NewTestMetadata()),
				Properties: azure.NewValue(make(map[string]azure.Value), types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	account := output.Accounts[0]
	assert.Equal(t, "", account.MinimumTLSVersion.Value())
	assert.False(t, account.EnforceHTTPS.Value())
	assert.True(t, account.PublicNetworkAccess.Value())

}

func Test_AdaptStorage(t *testing.T) {

	input := azure.Deployment{
		Resources: []azure.Resource{
			{
				Type: azure.NewValue("Microsoft.Storage/storageAccounts", types.NewTestMetadata()),
				Name: azure.Value{},
				Properties: azure.NewValue(map[string]azure.Value{
					"minimumTlsVersion":        azure.NewValue("TLS1_2", types.NewTestMetadata()),
					"supportsHttpsTrafficOnly": azure.NewValue(true, types.NewTestMetadata()),
					"publicNetworkAccess":      azure.NewValue("Disabled", types.NewTestMetadata()),
					"networkAcls": azure.NewValue(map[string]azure.Value{
						"bypass":        azure.NewValue("Logging, Metrics", types.NewTestMetadata()),
						"defaultAction": azure.NewValue("Allow", types.NewTestMetadata()),
					}, types.NewTestMetadata()),
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	expected := storage.Storage{
		Accounts: []storage.Account{{
			MinimumTLSVersion:   types.StringTest("TLS1_2"),
			EnforceHTTPS:        types.BoolTest(true),
			PublicNetworkAccess: types.BoolTest(false),
			NetworkRules: []storage.NetworkRule{{
				Bypass: []types.StringValue{
					types.StringTest("Logging"),
					types.StringTest("Metrics"),
				},
				AllowByDefault: types.BoolTest(true),
			}},
		}},
	}

	testutil.AssertDefsecEqual(t, expected, output)
}
