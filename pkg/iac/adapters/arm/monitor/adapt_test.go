package monitor

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected monitor.Monitor
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Insights/logprofiles",
      "properties": {}
    }
  ]
}`,
			expected: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{{}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Insights/logprofiles",
      "properties": {
        "retentionPolicy": {
		  "days": 20,
		  "enabled": true
		},
		"categories": ["Write"],
		"locations": ["global"]
      }
    }
  ]
}`,
			expected: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{{
					RetentionPolicy: monitor.RetentionPolicy{
						Enabled: types.BoolTest(true),
						Days:    types.IntTest(20),
					},
					Categories: []types.StringValue{types.StringTest("Write")},
					Locations:  []types.StringValue{types.StringTest("global")},
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
