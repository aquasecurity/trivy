package helm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_helmConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "yaml",
			filePath: "testdata/testchart/Chart.yaml",
			want:     true,
		},
		{
			name:     "yaml - shorthand",
			filePath: "testdata/testchart/templates/deployment.yml",
			want:     true,
		},
		{
			name:     "tpl",
			filePath: "testdata/testchart/templates/_helpers.tpl",
			want:     true,
		},
		{
			name:     "json",
			filePath: "testdata/testchart/values.yaml",
			want:     true,
		},
		{
			name:     "NOTES.txt",
			filePath: "testdata/testchart/templates/NOTES.txt",
			want:     false,
		},
		{
			name:     ".helmignore",
			filePath: "testdata/testchart/.helmignore",
			want:     true,
		},
		{
			name:     "testchart.tgz",
			filePath: filepath.Join("testdata", "testchart.tgz"),
			want:     true,
		},
		{
			name:     "testchart.tar.gz",
			filePath: filepath.Join("testdata", "testchart.tar.gz"),
			want:     true,
		},
		{
			name:     "nope.tgz",
			filePath: filepath.Join("testdata", "nope.tgz"),
			want:     true, // its a tarball after all
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := helmConfigAnalyzer{}

			info, _ := os.Stat(tt.filePath)

			got := s.Required(tt.filePath, info)
			assert.Equal(t, tt.want, got)
		})
	}
}
