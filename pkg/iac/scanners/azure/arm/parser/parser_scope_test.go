package parser

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_ParseScope(t *testing.T) {
	filename := "example.json"
	fsys := fstest.MapFS{
		filename: &fstest.MapFile{Data: []byte(`{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2025-06-01",
      "name": "sa"
    },
    {
      "type": "Microsoft.Insights/diagnosticSettings",
      "apiVersion": "2021-05-01-preview",
      "name": "blob-logs",
      "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/sa/blobServices/default",
      "properties": {
        "logs": [{"category": "StorageRead", "enabled": true}]
      }
    }
  ]
}`)},
	}

	deployments, err := New(fsys).ParseFS(t.Context(), ".")
	require.NoError(t, err)
	require.Len(t, deployments, 1)
	require.Len(t, deployments[0].Resources, 2)

	// The storage account has no scope in the template.
	assert.Empty(t, deployments[0].Resources[0].Scope.AsString())

	// The diagnostic setting keeps its scope, which the storage adapter
	// uses to match the setting to the account it targets.
	assert.Equal(t,
		"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/sa/blobServices/default",
		deployments[0].Resources[1].Scope.AsString())
}
