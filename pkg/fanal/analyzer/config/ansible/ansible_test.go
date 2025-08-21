package ansible

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func Test_ansibleConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "yaml",
			filePath: "test.yaml",
			want:     true,
		},
		{
			name:     "yml",
			filePath: "test.yml",
			want:     true,
		},
		{
			name:     "json",
			filePath: "test.json",
			want:     true,
		},
		{
			name:     "init",
			filePath: "test.ini",
			want:     true,
		},
		{
			name:     "without extension",
			filePath: "test",
			want:     true,
		},
		{
			name:     "config file",
			filePath: "ansible.cfg",
			want:     true,
		},
		{
			name:     "just cfg",
			filePath: "test.cfg",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newAnsibleConfigAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}
