package binary

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

func Test_rustBinaryLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/executable_rust",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.RustBinary,
						FilePath: "testdata/executable_rust",
						Libraries: types.Packages{
							{
								ID:        "crate_with_features@0.1.0",
								Name:      "crate_with_features",
								Version:   "0.1.0",
								DependsOn: []string{"library_crate@0.1.0"},
							},
							{
								ID:       "library_crate@0.1.0",
								Name:     "library_crate",
								Version:  "0.1.0",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name:      "not rust binary",
			inputFile: "testdata/executable_bash",
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

			a := rustBinaryLibraryAnalyzer{}
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

func Test_rustBinaryLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "executable file",
			filePath: lo.Ternary(runtime.GOOS == "windows", "testdata/binary.exe", "testdata/0755"),
			want:     true,
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
			a := rustBinaryLibraryAnalyzer{}
			fileInfo, err := os.Lstat(tt.filePath)
			require.NoError(t, err)
			got := a.Required(tt.filePath, fileInfo)
			assert.Equal(t, tt.want, got, fileInfo.Mode().Perm())
		})
	}
}
