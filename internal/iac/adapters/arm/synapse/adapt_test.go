package synapse

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/synapse"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected synapse.Synapse
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Synapse/workspaces",
      "properties": {}
    }
  ]
}`,
			expected: synapse.Synapse{
				Workspaces: []synapse.Workspace{{
					EnableManagedVirtualNetwork: types.BoolTest(false),
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Synapse/workspaces",
      "properties": {
        "managedVirtualNetwork": "default"
      }
    }
  ]
}`,
			expected: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						EnableManagedVirtualNetwork: types.BoolTest(true),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
