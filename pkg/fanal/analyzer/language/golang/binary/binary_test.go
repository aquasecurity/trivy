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

func Test_gobinaryLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/executable_gobinary",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoBinary,
						FilePath: "testdata/executable_gobinary",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-pep440-version",
								Version: "v0.0.0-20210121094942-22b2f8951d46",
							},
							{Name: "github.com/aquasecurity/go-version", Version: "v0.0.0-20210121072130-637058cfe492"},
							{Name: "golang.org/x/xerrors", Version: "v0.0.0-20200804184101-5ec99f83aff1"},
						},
					},
				},
			},
		},
		{
			name:      "not go binary",
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

			a := gobinaryLibraryAnalyzer{}
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

func Test_gobinaryLibraryAnalyzer_Required(t *testing.T) {
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
			a := gobinaryLibraryAnalyzer{}
			fileInfo, err := os.Lstat(tt.filePath)
			require.NoError(t, err)
			got := a.Required(tt.filePath, fileInfo)
			assert.Equal(t, tt.want, got, fileInfo.Mode().Perm())
		})
	}

}
