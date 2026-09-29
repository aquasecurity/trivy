package terraformplan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "/path/to/tfplan.json",
			want:     true,
		},
		{
			name:     "hcl",
			filePath: "/path/to/main.hcl",
			want:     false,
		},
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := terraformPlanConfigAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
