package authorization

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected authorization.Authorization
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Authorization/roleDefinitions",
      "properties": {}
    }
  ]
}`,
			expected: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{{}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Authorization/roleDefinitions",
      "properties": {
        "assignableScopes": [
          "/providers/Microsoft.Management/managementGroups/foo"
        ],
        "permissions": [
          {
            "actions": [
              "Microsoft.Compute/virtualMachines/read"
            ]
          }
        ]
      }
    }
  ]
}`,
			expected: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{{
					AssignableScopes: []types.StringValue{
						types.StringTest("/providers/Microsoft.Management/managementGroups/foo"),
					},
					Permissions: []authorization.Permission{{
						Actions: []types.StringValue{
							types.StringTest("Microsoft.Compute/virtualMachines/read"),
						},
					}},
				}},
			},
		},
		{
			name: "role assignment with complete properties",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Authorization/roleAssignments",
      "properties": {
        "scope": "/subscriptions/12345678-1234-1234-1234-123456789012",
        "roleDefinitionId": "/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "principalId": "11111111-1111-1111-1111-111111111111",
        "principalType": "User"
      }
    }
  ]
}`,
			expected: authorization.Authorization{
				RoleAssignments: []authorization.RoleAssignment{{
					RoleDefinitionId:   types.StringTest("/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"),
					RoleDefinitionName: types.String("", types.NewUnmanagedMetadata()),
					PrincipalId:        types.StringTest("11111111-1111-1111-1111-111111111111"),
					PrincipalType:      types.StringTest("User"),
				}},
			},
		},
		{
			name: "role assignment with missing properties",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Authorization/roleAssignments",
      "properties": {
        "scope": "/subscriptions/12345678-1234-1234-1234-123456789012"
      }
    }
  ]
}`,
			expected: authorization.Authorization{
				RoleAssignments: []authorization.RoleAssignment{{
					RoleDefinitionId:   types.StringTest(""),
					RoleDefinitionName: types.String("", types.NewUnmanagedMetadata()),
					PrincipalId:        types.StringTest(""),
					PrincipalType:      types.StringTest(""),
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
