package azurearm

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_azureARMConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "json",
			filePath: "test.json",
			want:     true,
		},
		{
			name:     "yaml",
			filePath: "test.yaml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newAzureARMConfigAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}
