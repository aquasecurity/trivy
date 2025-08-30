package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptRoleDefinition(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  authorization.RoleDefinition
	}{
		{
			name: "wildcard actions and data reference scope",
			terraform: `
			resource "azurerm_role_definition" "example" {
				name        = "my-custom-role"
	  
				permissions {
				  actions     = ["*"]
				  not_actions = []
				}

				assignable_scopes = [
				  data.azurerm_subscription.primary.id,
				]
			}
`,
			expected: authorization.RoleDefinition{
				Metadata: iacTypes.NewTestMetadata(),
				Permissions: []authorization.Permission{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Actions: []iacTypes.StringValue{
							iacTypes.String("*", iacTypes.NewTestMetadata()),
						},
					},
				},
				AssignableScopes: []iacTypes.StringValue{
					iacTypes.StringUnresolvable(iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "no actions and wildcard scope",
			terraform: `
			resource "azurerm_role_definition" "example" {
				name        = "my-custom-role"
	  
				permissions {
				  actions     = []
				  not_actions = []
				}

				assignable_scopes = [
					"/"
				]
			}
`,
			expected: authorization.RoleDefinition{
				Metadata: iacTypes.NewTestMetadata(),
				Permissions: []authorization.Permission{
					{
						Metadata: iacTypes.NewTestMetadata(),
					},
				},
				AssignableScopes: []iacTypes.StringValue{
					iacTypes.String("/", iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRoleDefinition(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_role_definition" "example" {
		name        = "my-custom-role"

		permissions {
		  actions     = ["*"]
		  not_actions = []
		}

		assignable_scopes = ["/"]
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.RoleDefinitions, 1)
	require.Len(t, adapted.RoleDefinitions[0].Permissions, 1)
	require.Len(t, adapted.RoleDefinitions[0].AssignableScopes, 1)

	assert.Equal(t, 6, adapted.RoleDefinitions[0].Permissions[0].Actions[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, adapted.RoleDefinitions[0].Permissions[0].Actions[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, adapted.RoleDefinitions[0].AssignableScopes[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, adapted.RoleDefinitions[0].AssignableScopes[0].GetMetadata().Range().GetEndLine())

}

func Test_adaptRoleAssignment(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  authorization.RoleAssignment
	}{
		{
			name: "complete role assignment",
			terraform: `
			resource "azurerm_role_assignment" "example" {
				scope                = "/subscriptions/12345678-1234-1234-1234-123456789012"
				role_definition_id   = "/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
				role_definition_name = "Owner"
				principal_id         = "11111111-1111-1111-1111-111111111111"
				principal_type       = "User"
			}
`,
			expected: authorization.RoleAssignment{
				Metadata:           iacTypes.NewTestMetadata(),
				Scope:              iacTypes.String("/subscriptions/12345678-1234-1234-1234-123456789012", iacTypes.NewTestMetadata()),
				RoleDefinitionId:   iacTypes.String("/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", iacTypes.NewTestMetadata()),
				RoleDefinitionName: iacTypes.String("Owner", iacTypes.NewTestMetadata()),
				PrincipalId:        iacTypes.String("11111111-1111-1111-1111-111111111111", iacTypes.NewTestMetadata()),
				PrincipalType:      iacTypes.String("User", iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "data reference scope (unresolvable)",
			terraform: `
			resource "azurerm_role_assignment" "example" {
				scope                = data.azurerm_resource_group.example.id
				role_definition_id   = "/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/reader"
				principal_id         = "33333333-3333-3333-3333-333333333333"
			}
`,
			expected: authorization.RoleAssignment{
				Metadata:           iacTypes.NewTestMetadata(),
				Scope:              iacTypes.StringUnresolvable(iacTypes.NewTestMetadata()),
				RoleDefinitionId:   iacTypes.String("/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/reader", iacTypes.NewTestMetadata()),
				RoleDefinitionName: iacTypes.String("", iacTypes.NewTestMetadata()),
				PrincipalId:        iacTypes.String("33333333-3333-3333-3333-333333333333", iacTypes.NewTestMetadata()),
				PrincipalType:      iacTypes.String("", iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRoleAssignment(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
