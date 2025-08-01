package parser

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/resolver"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func createMetadata(targetFS fs.FS, filename string, start, end int, ref string, parent *types.Metadata) types.Metadata {
	child := types.NewMetadata(types.NewRange(filename, start, end, "", targetFS), ref)
	if parent != nil {
		child.SetParentPtr(parent)
	}
	return child
}

func TestParser_Parse(t *testing.T) {
	filename := "example.json"

	tests := []struct {
		name           string
		input          string
		want           func(fsys fs.FS) azure.Deployment
		wantDeployment bool
	}{
		{
			name: "basic param",
			input: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", // another one
  "contentVersion": "1.0.0.0",
  "parameters": {
    "storagePrefix": {
      "type": "string",
      "defaultValue": "x",
      "maxLength": 11,
      "minLength": 3
    }
  },
  "resources": []
}`,
			want: func(fsys fs.FS) azure.Deployment {
				root := createMetadata(fsys, filename, 0, 0, "", nil).WithInternal(resolver.NewResolver())
				metadata := createMetadata(fsys, filename, 1, 13, "", &root)
				storageMetadata := createMetadata(fsys, filename, 5, 10, "parameters.storagePrefix", &metadata)

				return azure.Deployment{
					Metadata:    metadata,
					TargetScope: azure.ScopeResourceGroup,
					Parameters: []azure.Parameter{
						{
							Variable: azure.Variable{
								Name:  "storagePrefix",
								Value: azure.NewValue("x", createMetadata(fsys, filename, 7, 7, "parameters.storagePrefix.defaultValue", &storageMetadata)),
							},
							Default:    azure.NewValue("x", createMetadata(fsys, filename, 7, 7, "parameters.storagePrefix.defaultValue", &storageMetadata)),
							Decorators: nil,
						},
					},
				}
			},
			wantDeployment: true,
		},
		{
			name: "storageAccount",
			input: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", // another one
  "contentVersion": "1.0.0.0",
  "parameters": {},
  "resources": [
{
  "type": "Microsoft.Storage/storageAccounts",
  "apiVersion": "2022-05-01",
  "name": "myResource",
  "location": "string",
  "tags": {
    "tagName1": "tagValue1",
    "tagName2": "tagValue2"
  },
  "sku": {
    "name": "string"
  },
  "kind": "string",
  "extendedLocation": {
    "name": "string",
    "type": "EdgeZone"
  },
  "identity": {
    "type": "string",
    "userAssignedIdentities": {}
  },
  "properties": {
    "allowSharedKeyAccess":false,
    "customDomain": {
      "name": "string",
      "useSubDomainName":false,
      "number": 123,
	  "expr": "[toLower('Production')]"
    },
    "networkAcls": [
		{
			"bypass": "AzureServices1"
		},
		{
			"bypass": "AzureServices2"
		}
	]
  }
}
]
}`,
			want: func(fsys fs.FS) azure.Deployment {
				rootMetadata := createMetadata(fsys, filename, 0, 0, "", nil).WithInternal(resolver.NewResolver())
				fileMetadata := createMetadata(fsys, filename, 1, 46, "", &rootMetadata)

				resourceMetadata := createMetadata(fsys, filename, 6, 44, "resources[0]", &fileMetadata)

				propertiesMetadata := createMetadata(fsys, filename, 27, 43, "resources[0].properties", &resourceMetadata)
				customDomainMetadata := createMetadata(fsys, filename, 29, 34, "resources[0].properties.customDomain", &propertiesMetadata)
				networkACLListMetadata := createMetadata(fsys, filename, 35, 42, "resources[0].properties.networkAcls", &propertiesMetadata)

				networkACL0Metadata := createMetadata(fsys, filename, 36, 38, "resources[0].properties.networkAcls[0]", &networkACLListMetadata)
				networkACL1Metadata := createMetadata(fsys, filename, 39, 41, "resources[0].properties.networkAcls[1]", &networkACLListMetadata)

				return azure.Deployment{
					Metadata:    fileMetadata,
					TargetScope: azure.ScopeResourceGroup,
					Resources: []azure.Resource{
						{
							Metadata: resourceMetadata,
							APIVersion: azure.NewValue(
								"2022-05-01",
								createMetadata(fsys, filename, 8, 8, "resources[0].apiVersion", &resourceMetadata),
							),
							Type: azure.NewValue(
								"Microsoft.Storage/storageAccounts",
								createMetadata(fsys, filename, 7, 7, "resources[0].type", &resourceMetadata),
							),
							Kind: azure.NewValue(
								"string",
								createMetadata(fsys, filename, 18, 18, "resources[0].kind", &resourceMetadata),
							),
							Name: azure.NewValue(
								"myResource",
								createMetadata(fsys, filename, 9, 9, "resources[0].name", &resourceMetadata),
							),
							Location: azure.NewValue(
								"string",
								createMetadata(fsys, filename, 10, 10, "resources[0].location", &resourceMetadata),
							),
							Properties: azure.NewValue(
								map[string]azure.Value{
									"allowSharedKeyAccess": azure.NewValue(false, createMetadata(fsys, filename, 28, 28, "resources[0].properties.allowSharedKeyAccess", &propertiesMetadata)),
									"customDomain": azure.NewValue(
										map[string]azure.Value{
											"name":             azure.NewValue("string", createMetadata(fsys, filename, 30, 30, "resources[0].properties.customDomain.name", &customDomainMetadata)),
											"useSubDomainName": azure.NewValue(false, createMetadata(fsys, filename, 31, 31, "resources[0].properties.customDomain.useSubDomainName", &customDomainMetadata)),
											"number":           azure.NewValue(int64(123), createMetadata(fsys, filename, 32, 32, "resources[0].properties.customDomain.number", &customDomainMetadata)),
											"expr":             azure.NewExprValue("toLower('Production')", createMetadata(fsys, filename, 33, 33, "resources[0].properties.customDomain.expr", &customDomainMetadata)),
										}, customDomainMetadata),
									"networkAcls": azure.NewValue(
										[]azure.Value{
											azure.NewValue(
												map[string]azure.Value{
													"bypass": azure.NewValue("AzureServices1", createMetadata(fsys, filename, 37, 37, "resources[0].properties.networkAcls[0].bypass", &networkACL0Metadata)),
												},
												networkACL0Metadata,
											),
											azure.NewValue(
												map[string]azure.Value{
													"bypass": azure.NewValue("AzureServices2", createMetadata(fsys, filename, 40, 40, "resources[0].properties.networkAcls[1].bypass", &networkACL1Metadata)),
												},
												networkACL1Metadata,
											),
										}, networkACLListMetadata),
								},
								propertiesMetadata,
							),
						},
					},
				}
			},

			wantDeployment: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				filename: &fstest.MapFile{Data: []byte(tt.input)},
			}
			p := New(fsys)
			got, err := p.ParseFS(t.Context(), ".")
			require.NoError(t, err)

			if !tt.wantDeployment {
				assert.Empty(t, got)
				return
			}

			require.Len(t, got, 1)
			want := tt.want(fsys)
			assert.Equal(t, want, got[0])
		})
	}
}

func Test_NestedResourceParsing(t *testing.T) {
	input := `
{
  "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "environment": {
      "type": "string",
      "allowedValues": [
        "dev",
        "test",
        "prod"
      ]
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]",
      "metadata": {
        "description": "Location for all resources."
      }
    },
    "storageAccountSkuName": {
      "type": "string",
      "defaultValue": "Standard_LRS"
    },
    "storageAccountSkuTier": {
      "type": "string",
      "defaultValue": "Standard"
    }
  },
  "variables": {
    "uniquePart": "[take(uniqueString(resourceGroup().id), 4)]",
    "storageAccountName": "[concat('mystorageaccount', variables('uniquePart'), parameters('environment'))]",
    "queueName": "myqueue"
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "[variables('storageAccountName')]",
      "location": "[parameters('location')]",
      "apiVersion": "2019-06-01",
      "sku": {
        "name": "[parameters('storageAccountSkuName')]",
        "tier": "[parameters('storageAccountSkuTier')]"
      },
      "kind": "StorageV2",
      "properties": {},
      "resources": [
        {
          "name": "[concat('default/', variables('queueName'))]",
          "type": "queueServices/queues",
          "apiVersion": "2019-06-01",
          "dependsOn": [
            "[variables('storageAccountName')]"
          ],
          "properties": {
            "metadata": {}
          }
        }
      ]
    }
  ]
}
`

	fsys := fstest.MapFS{
		"nested.json": &fstest.MapFile{Data: []byte(input)},
	}

	p := New(fsys)
	got, err := p.ParseFS(t.Context(), ".")
	require.NoError(t, err)
	require.Len(t, got, 1)

	deployment := got[0]

	require.Len(t, deployment.Resources, 1)

	storageAccountResource := deployment.Resources[0]

	require.Len(t, storageAccountResource.Resources, 1)

	queue := storageAccountResource.Resources[0]

	assert.Equal(t, "queueServices/queues", queue.Type.AsString())
}
