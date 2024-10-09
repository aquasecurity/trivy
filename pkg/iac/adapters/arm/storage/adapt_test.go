package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	account := output.Accounts[0]
	assert.Equal(t, "TLS1_2", account.MinimumTLSVersion.Value())
	assert.True(t, account.EnforceHTTPS.Value())
	assert.False(t, account.PublicNetworkAccess.Value())

}
