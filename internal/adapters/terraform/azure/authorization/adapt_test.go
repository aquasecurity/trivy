package authorization

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/authorization"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				Metadata: defsecTypes.NewTestMetadata(),
				Permissions: []authorization.Permission{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Actions: []defsecTypes.StringValue{
							defsecTypes.String("*", defsecTypes.NewTestMetadata()),
						},
					},
				},
				AssignableScopes: []defsecTypes.StringValue{
					defsecTypes.StringUnresolvable(defsecTypes.NewTestMetadata()),
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
				Metadata: defsecTypes.NewTestMetadata(),
				Permissions: []authorization.Permission{
					{
						Metadata: defsecTypes.NewTestMetadata(),
					},
				},
				AssignableScopes: []defsecTypes.StringValue{
					defsecTypes.String("/", defsecTypes.NewTestMetadata()),
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
