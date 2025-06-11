package datafactory

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datafactory"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected datafactory.DataFactory
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DataFactory/factories",
      "properties": {}
    }
  ]
}`,
			expected: datafactory.DataFactory{
				DataFactories: []datafactory.Factory{{
					EnablePublicNetwork: types.BoolTest(true),
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DataFactory/factories",
      "properties": {
        "publicNetworkAccess": "Disabled"
      }
    }
  ]
}`,
			expected: datafactory.DataFactory{
				DataFactories: []datafactory.Factory{{
					EnablePublicNetwork: types.BoolTest(true),
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
