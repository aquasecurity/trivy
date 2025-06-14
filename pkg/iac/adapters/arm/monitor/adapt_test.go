package monitor

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
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
			expected: monitor.Monitor{},
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
			expected: monitor.Monitor{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
