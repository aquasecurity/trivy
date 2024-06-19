package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	assert.Equal(t, "TLS1_0", account.MinimumTLSVersion.Value())
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
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	account := output.Accounts[0]
	assert.Equal(t, "TLS1_2", account.MinimumTLSVersion.Value())
	assert.True(t, account.EnforceHTTPS.Value())

}
