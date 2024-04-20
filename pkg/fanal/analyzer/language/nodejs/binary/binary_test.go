package generic

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_nodejsBinaryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/node",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodeJsGeneric,
						FilePath: "testdata/node",
						Libraries: types.Packages{
							{
								ID:        "node@12.16.3",
								Name:      "node",
								Version:   "12.16.3",
							},
						},
					},
				},
			},
		},
		{
			name:      "not node binary",
			inputFile: "testdata/dummy",
		},
		{
			name:      "broken elf",
			inputFile: "testdata/broken_elf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := nodejsBinaryAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}


func Test_nodejsBinaryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "Python binary",
			filePath: "testdata/node",
			want:     true,
		},
		{
			name:     "executable file",
			filePath: lo.Ternary(runtime.GOOS == "windows", "testdata/binary.exe", "testdata/0755"),
			want:     false,
		},
		{
			name:     "file perm 0644",
			filePath: "testdata/0644",
			want:     false,
		},
		{
			name:     "symlink",
			filePath: "testdata/symlink",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := nodejsBinaryAnalyzer{}
			fileInfo, err := os.Lstat(tt.filePath)
			require.NoError(t, err)
			got := a.Required(tt.filePath, fileInfo)
			assert.Equal(t, tt.want, got, fileInfo.Mode().Perm())
		})
	}
}
