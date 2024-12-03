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
			name:     "tfplan as extension",
			filePath: "/path/to/test.tfplan",
			want:     true,
		},
		{
			name:     "without extension",
			filePath: "/path/to/tfplan",
			want:     true,
		},
		{
			name:     "bad path",
			filePath: "/path/to/mytfplan.txt",
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
