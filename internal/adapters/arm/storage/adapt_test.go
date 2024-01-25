package storage

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/scanners/azure"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/stretchr/testify/require"
)

func Test_AdaptStorageDefaults(t *testing.T) {

	input := azure.Deployment{
		Resources: []azure.Resource{
			{
				Type:       azure.NewValue("Microsoft.Storage/storageAccounts", types.NewTestMetadata()),
				Properties: azure.NewValue(map[string]azure.Value{}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	account := output.Accounts[0]
	assert.Equal(t, "TLS1_0", account.MinimumTLSVersion.Value())
	assert.Equal(t, false, account.EnforceHTTPS.Value())

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
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.Accounts, 1)

	account := output.Accounts[0]
	assert.Equal(t, "TLS1_2", account.MinimumTLSVersion.Value())
	assert.Equal(t, true, account.EnforceHTTPS.Value())

}
