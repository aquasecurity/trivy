package helm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_helmConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "yaml",
			filePath: "Chart.yaml",
			want:     true,
		},
		{
			name:     "yaml - shorthand",
			filePath: "templates/deployment.yml",
			want:     true,
		},
		{
			name:     "tpl",
			filePath: "templates/_helpers.tpl",
			want:     true,
		},
		{
			name:     "json",
			filePath: "values.json",
			want:     true,
		},
		{
			name:     "NOTES.txt",
			filePath: "templates/NOTES.txt",
			want:     false,
		},
		{
			name:     ".helmignore",
			filePath: ".helmignore",
			want:     true,
		},
		{
			name:     "testchart.tgz",
			filePath: "testchart.tgz",
			want:     true,
		},
		{
			name:     "testchart.tar.gz",
			filePath: "testchart.tar.gz",
			want:     true,
		},
		{
			name:     "nope.tgz",
			filePath: "nope.tgz",
			want:     true, // it's a tarball after all
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := helmConfigAnalyzer{}

			// Create a dummy file info
			info, err := os.Stat("./helm_test.go")
			require.NoError(t, err)

			got := s.Required(tt.filePath, info)
			assert.Equal(t, tt.want, got)
		})
	}
}
