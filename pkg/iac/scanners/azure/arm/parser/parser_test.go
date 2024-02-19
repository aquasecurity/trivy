package parser

import (
	"context"
	"io/fs"
	"os"
	"testing"

	azure2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/resolver"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/liamg/memoryfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
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

	targetFS := memoryfs.New()

	tests := []struct {
		name           string
		input          string
		want           func() azure2.Deployment
		wantDeployment bool
	}{
		{
			name:           "invalid code",
			input:          `blah`,
			wantDeployment: false,
		},
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
			want: func() azure2.Deployment {

				root := createMetadata(targetFS, filename, 0, 0, "", nil).WithInternal(resolver.NewResolver())
				metadata := createMetadata(targetFS, filename, 1, 13, "", &root)
				parametersMetadata := createMetadata(targetFS, filename, 4, 11, "parameters", &metadata)
				storageMetadata := createMetadata(targetFS, filename, 5, 10, "parameters.storagePrefix", &parametersMetadata)

				return azure2.Deployment{
					Metadata:    metadata,
					TargetScope: azure2.ScopeResourceGroup,
					Parameters: []azure2.Parameter{
						{
							Variable: azure2.Variable{
								Name:  "storagePrefix",
								Value: azure2.NewValue("x", createMetadata(targetFS, filename, 7, 7, "parameters.storagePrefix.defaultValue", &storageMetadata)),
							},
							Default:    azure2.NewValue("x", createMetadata(targetFS, filename, 7, 7, "parameters.storagePrefix.defaultValue", &storageMetadata)),
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
      "number": 123
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
			want: func() azure2.Deployment {

				rootMetadata := createMetadata(targetFS, filename, 0, 0, "", nil).WithInternal(resolver.NewResolver())
				fileMetadata := createMetadata(targetFS, filename, 1, 45, "", &rootMetadata)
				resourcesMetadata := createMetadata(targetFS, filename, 5, 44, "resources", &fileMetadata)

				resourceMetadata := createMetadata(targetFS, filename, 6, 43, "resources[0]", &resourcesMetadata)

				propertiesMetadata := createMetadata(targetFS, filename, 27, 42, "resources[0].properties", &resourceMetadata)

				customDomainMetadata := createMetadata(targetFS, filename, 29, 33, "resources[0].properties.customDomain", &propertiesMetadata)
				networkACLListMetadata := createMetadata(targetFS, filename, 34, 41, "resources[0].properties.networkAcls", &propertiesMetadata)

				networkACL0Metadata := createMetadata(targetFS, filename, 35, 37, "resources[0].properties.networkAcls[0]", &networkACLListMetadata)
				networkACL1Metadata := createMetadata(targetFS, filename, 38, 40, "resources[0].properties.networkAcls[1]", &networkACLListMetadata)

				return azure2.Deployment{
					Metadata:    fileMetadata,
					TargetScope: azure2.ScopeResourceGroup,
					Resources: []azure2.Resource{
						{
							Metadata: resourceMetadata,
							APIVersion: azure2.NewValue(
								"2022-05-01",
								createMetadata(targetFS, filename, 8, 8, "resources[0].apiVersion", &resourceMetadata),
							),
							Type: azure2.NewValue(
								"Microsoft.Storage/storageAccounts",
								createMetadata(targetFS, filename, 7, 7, "resources[0].type", &resourceMetadata),
							),
							Kind: azure2.NewValue(
								"string",
								createMetadata(targetFS, filename, 18, 18, "resources[0].kind", &resourceMetadata),
							),
							Name: azure2.NewValue(
								"myResource",
								createMetadata(targetFS, filename, 9, 9, "resources[0].name", &resourceMetadata),
							),
							Location: azure2.NewValue(
								"string",
								createMetadata(targetFS, filename, 10, 10, "resources[0].location", &resourceMetadata),
							),
							Properties: azure2.NewValue(
								map[string]azure2.Value{
									"allowSharedKeyAccess": azure2.NewValue(false, createMetadata(targetFS, filename, 28, 28, "resources[0].properties.allowSharedKeyAccess", &propertiesMetadata)),
									"customDomain": azure2.NewValue(
										map[string]azure2.Value{
											"name":             azure2.NewValue("string", createMetadata(targetFS, filename, 30, 30, "resources[0].properties.customDomain.name", &customDomainMetadata)),
											"useSubDomainName": azure2.NewValue(false, createMetadata(targetFS, filename, 31, 31, "resources[0].properties.customDomain.useSubDomainName", &customDomainMetadata)),
											"number":           azure2.NewValue(int64(123), createMetadata(targetFS, filename, 32, 32, "resources[0].properties.customDomain.number", &customDomainMetadata)),
										}, customDomainMetadata),
									"networkAcls": azure2.NewValue(
										[]azure2.Value{
											azure2.NewValue(
												map[string]azure2.Value{
													"bypass": azure2.NewValue("AzureServices1", createMetadata(targetFS, filename, 36, 36, "resources[0].properties.networkAcls[0].bypass", &networkACL0Metadata)),
												},
												networkACL0Metadata,
											),
											azure2.NewValue(
												map[string]azure2.Value{
													"bypass": azure2.NewValue("AzureServices2", createMetadata(targetFS, filename, 39, 39, "resources[0].properties.networkAcls[1].bypass", &networkACL1Metadata)),
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

			require.NoError(t, targetFS.WriteFile(filename, []byte(tt.input), 0644))

			p := New(targetFS, options.ParserWithDebug(os.Stderr))
			got, err := p.ParseFS(context.Background(), ".")
			require.NoError(t, err)

			if !tt.wantDeployment {
				assert.Len(t, got, 0)
				return
			}

			require.Len(t, got, 1)
			want := tt.want()
			g := got[0]

			require.Equal(t, want, g)
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

	targetFS := memoryfs.New()

	require.NoError(t, targetFS.WriteFile("nested.json", []byte(input), 0644))

	p := New(targetFS, options.ParserWithDebug(os.Stderr))
	got, err := p.ParseFS(context.Background(), ".")
	require.NoError(t, err)
	require.Len(t, got, 1)

	deployment := got[0]

	require.Len(t, deployment.Resources, 1)

	storageAccountResource := deployment.Resources[0]

	require.Len(t, storageAccountResource.Resources, 1)

	queue := storageAccountResource.Resources[0]

	assert.Equal(t, "queueServices/queues", queue.Type.AsString())
}

//
// func Test_JsonFile(t *testing.T) {
//
// 	input, err := os.ReadFile("testdata/postgres.json")
// 	require.NoError(t, err)
//
// 	targetFS := memoryfs.New()
//
// 	require.NoError(t, targetFS.WriteFile("postgres.json", input, 0644))
//
// 	p := New(targetFS, options.ParserWithDebug(os.Stderr))
// 	got, err := p.ParseFS(context.Background(), ".")
// 	require.NoError(t, err)
//
// 	got[0].Resources[3].Name.Resolve()
//
// 	name := got[0].Resources[3].Name.AsString()
// 	assert.Equal(t, "myserver", name)
//
// }
