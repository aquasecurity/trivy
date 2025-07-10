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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
