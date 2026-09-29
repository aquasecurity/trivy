package datalake

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datalake"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected datalake.DataLake
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DataLakeStore/accounts",
      "properties": {}
    }
  ]
}`,
			expected: datalake.DataLake{
				Stores: []datalake.Store{{
					EnableEncryption: types.BoolTest(false),
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DataLakeStore/accounts",
      "properties": {
        "encryptionState": "Enabled"
      }
    }
  ]
}`,
			expected: datalake.DataLake{
				Stores: []datalake.Store{{
					EnableEncryption: types.BoolTest(true),
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
