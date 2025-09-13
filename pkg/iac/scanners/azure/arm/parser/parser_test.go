package parser

import (
	"io/fs"
	"testing"

	"github.com/liamg/memoryfs"
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

	targetFS := memoryfs.New()

	tests := []struct {
		name           string
		input          string
		want           func() azure.Deployment
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
			want: func() azure.Deployment {
				root := createMetadata(targetFS, filename, 0, 0, "", nil).WithInternal(resolver.NewResolver())
				metadata := createMetadata(targetFS, filename, 1, 13, "", &root)
				storageMetadata := createMetadata(targetFS, filename, 5, 10, "parameters.storagePrefix", &metadata)

				return azure.Deployment{
					Metadata:    metadata,
					TargetScope: azure.ScopeResourceGroup,
					Parameters: []azure.Parameter{
						{
							Variable: azure.Variable{
								Name:  "storagePrefix",
								Value: azure.NewValue("x", createMetadata(targetFS, filename, 7, 7, "parameters.storagePrefix.defaultValue", &storageMetadata)),
							},
							Default:    azure.NewValue("x", createMetadata(targetFS, filename, 7, 7, "parameters.storagePrefix.defaultValue", &storageMetadata)),
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
			want: func() azure.Deployment {
				rootMetadata := createMetadata(targetFS, filename, 0, 0, "", nil).WithInternal(resolver.NewResolver())
				fileMetadata := createMetadata(targetFS, filename, 1, 46, "", &rootMetadata)

				resourceMetadata := createMetadata(targetFS, filename, 6, 44, "resources[0]", &fileMetadata)

				propertiesMetadata := createMetadata(targetFS, filename, 27, 43, "resources[0].properties", &resourceMetadata)

				customDomainMetadata := createMetadata(targetFS, filename, 29, 34, "resources[0].properties.customDomain", &propertiesMetadata)
				networkACLListMetadata := createMetadata(targetFS, filename, 35, 42, "resources[0].properties.networkAcls", &propertiesMetadata)

				networkACL0Metadata := createMetadata(targetFS, filename, 36, 38, "resources[0].properties.networkAcls[0]", &networkACLListMetadata)
				networkACL1Metadata := createMetadata(targetFS, filename, 39, 41, "resources[0].properties.networkAcls[1]", &networkACLListMetadata)

				return azure.Deployment{
					Metadata:    fileMetadata,
					TargetScope: azure.ScopeResourceGroup,
					Resources: []azure.Resource{
						{
							Metadata: resourceMetadata,
							APIVersion: azure.NewValue(
								"2022-05-01",
								createMetadata(targetFS, filename, 8, 8, "resources[0].apiVersion", &resourceMetadata),
							),
							Type: azure.NewValue(
								"Microsoft.Storage/storageAccounts",
								createMetadata(targetFS, filename, 7, 7, "resources[0].type", &resourceMetadata),
							),
							Kind: azure.NewValue(
								"string",
								createMetadata(targetFS, filename, 18, 18, "resources[0].kind", &resourceMetadata),
							),
							Name: azure.NewValue(
								"myResource",
								createMetadata(targetFS, filename, 9, 9, "resources[0].name", &resourceMetadata),
							),
							Location: azure.NewValue(
								"string",
								createMetadata(targetFS, filename, 10, 10, "resources[0].location", &resourceMetadata),
							),
							Properties: azure.NewValue(
								map[string]azure.Value{
									"allowSharedKeyAccess": azure.NewValue(false, createMetadata(targetFS, filename, 28, 28, "resources[0].properties.allowSharedKeyAccess", &propertiesMetadata)),
									"customDomain": azure.NewValue(
										map[string]azure.Value{
											"name":             azure.NewValue("string", createMetadata(targetFS, filename, 30, 30, "resources[0].properties.customDomain.name", &customDomainMetadata)),
											"useSubDomainName": azure.NewValue(false, createMetadata(targetFS, filename, 31, 31, "resources[0].properties.customDomain.useSubDomainName", &customDomainMetadata)),
											"number":           azure.NewValue(int64(123), createMetadata(targetFS, filename, 32, 32, "resources[0].properties.customDomain.number", &customDomainMetadata)),
											"expr":             azure.NewExprValue("toLower('Production')", createMetadata(targetFS, filename, 33, 33, "resources[0].properties.customDomain.expr", &customDomainMetadata)),
										}, customDomainMetadata),
									"networkAcls": azure.NewValue(
										[]azure.Value{
											azure.NewValue(
												map[string]azure.Value{
													"bypass": azure.NewValue("AzureServices1", createMetadata(targetFS, filename, 37, 37, "resources[0].properties.networkAcls[0].bypass", &networkACL0Metadata)),
												},
												networkACL0Metadata,
											),
											azure.NewValue(
												map[string]azure.Value{
													"bypass": azure.NewValue("AzureServices2", createMetadata(targetFS, filename, 40, 40, "resources[0].properties.networkAcls[1].bypass", &networkACL1Metadata)),
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
			require.NoError(t, targetFS.WriteFile(filename, []byte(tt.input), 0o644))

			p := New(targetFS)
			got, err := p.ParseFS(t.Context(), ".")
			require.NoError(t, err)

			if !tt.wantDeployment {
				assert.Empty(t, got)
				return
			}

			require.Len(t, got, 1)
			want := tt.want()
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

	targetFS := memoryfs.New()

	require.NoError(t, targetFS.WriteFile("nested.json", []byte(input), 0o644))

	p := New(targetFS)
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

func TestParser_Parse_DictionaryResources(t *testing.T) {
	// Test case for Bicep modules that generate dictionary-style resources
	input := `{
  "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
  "languageVersion": "2.0",
  "contentVersion": "1.0.0.0",
  "metadata": {
    "_generator": {
      "name": "bicep",
      "version": "0.37.4.10188",
      "templateHash": "9375790898027716067"
    }
  },
  "resources": {
    "myrg": {
      "type": "Microsoft.Resources/resourceGroups",
      "apiVersion": "2025-04-01",
      "name": "myrg",
      "location": "WestEurope"
    },
    "insecure": {
      "type": "Microsoft.Resources/deployments",
      "apiVersion": "2022-09-01",
      "name": "[format('insecure-{0}', uniqueString('insecure', deployment().name))]",
      "resourceGroup": "myrg",
      "properties": {
        "expressionEvaluationOptions": {
          "scope": "inner"
        },
        "mode": "Incremental",
        "template": {
          "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
          "contentVersion": "1.0.0.0",
          "metadata": {
            "_generator": {
              "name": "bicep",
              "version": "0.37.4.10188",
              "templateHash": "1574586486505528430"
            }
          },
          "resources": [
            {
              "type": "Microsoft.Storage/storageAccounts",
              "apiVersion": "2022-09-01",
              "name": "[format('insecurestorage{0}', uniqueString(resourceGroup().id))]",
              "location": "[resourceGroup().location]",
              "sku": {
                "name": "Standard_LRS"
              },
              "kind": "StorageV2",
              "properties": {
                "allowBlobPublicAccess": true,
                "minimumTlsVersion": "TLS1_0",
                "supportsHttpsTrafficOnly": false,
                "accessTier": "Hot"
              }
            }
          ]
        }
      },
      "dependsOn": [
        "myrg"
      ]
    }
  }
}`

	targetFS := memoryfs.New()
	filename := "dictionary_resources.json"

	require.NoError(t, targetFS.WriteFile(filename, []byte(input), 0o644))

	p := New(targetFS)
	got, err := p.ParseFS(t.Context(), ".")
	require.NoError(t, err)
	
	require.Len(t, got, 1)

	deployment := got[0]

	// Should have 3 resources: myrg, insecure, and the nested storage account from insecure
	require.Len(t, deployment.Resources, 3)

	// Check that resources are properly parsed
	resourceNames := make([]string, len(deployment.Resources))
	for i, resource := range deployment.Resources {
		resourceNames[i] = resource.Name.AsString()
	}

	// Should contain both resources from the dictionary
	assert.Contains(t, resourceNames, "myrg")
	assert.Contains(t, resourceNames, "[format('insecure-{0}', uniqueString('insecure', deployment().name))]")

	// Check that the resource types are correct
	resourceTypes := make([]string, len(deployment.Resources))
	for i, resource := range deployment.Resources {
		resourceTypes[i] = resource.Type.AsString()
	}

	assert.Contains(t, resourceTypes, "Microsoft.Resources/resourceGroups")
	assert.Contains(t, resourceTypes, "Microsoft.Resources/deployments")
}
