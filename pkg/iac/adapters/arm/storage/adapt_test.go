package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	azure2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_AdaptStorageDefaults(t *testing.T) {

	input := azure2.Deployment{
		Resources: []azure2.Resource{
			{
				Type:       azure2.NewValue("Microsoft.Storage/storageAccounts", types.NewTestMetadata()),
				Properties: azure2.NewValue(make(map[string]azure2.Value), types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	account := output.Accounts[0]
	assert.Equal(t, "", account.MinimumTLSVersion.Value())
	assert.False(t, account.EnforceHTTPS.Value())

}

func Test_AdaptStorage(t *testing.T) {

	input := azure2.Deployment{
		Resources: []azure2.Resource{
			{
				Type: azure2.NewValue("Microsoft.Storage/storageAccounts", types.NewTestMetadata()),
				Name: azure2.Value{},
				Properties: azure2.NewValue(map[string]azure2.Value{
					"minimumTlsVersion":        azure2.NewValue("TLS1_2", types.NewTestMetadata()),
					"supportsHttpsTrafficOnly": azure2.NewValue(true, types.NewTestMetadata()),
					"networkAcls": azure2.NewValue(map[string]azure2.Value{
						"bypass":        azure2.NewValue("Logging, Metrics", types.NewTestMetadata()),
						"defaultAction": azure2.NewValue("Allow", types.NewTestMetadata()),
					}, types.NewTestMetadata()),
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	expected := storage.Storage{
		Accounts: []storage.Account{{
			MinimumTLSVersion: types.StringTest("TLS1_2"),
			EnforceHTTPS:      types.BoolTest(true),
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
