package conan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_conanLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Conan,
						FilePath: "testdata/happy.lock",
						Libraries: types.Packages{
							{
								ID:      "openssl/3.0.5",
								Name:    "openssl",
								Version: "3.0.5",
								DependsOn: []string{
									"zlib/1.2.12",
								},
							},
							{
								ID:       "zlib/1.2.12",
								Name:     "zlib",
								Version:  "1.2.12",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name:      "empty file",
			inputFile: "testdata/empty.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := conanLockAnalyzer{}
			got, err := a.Analyze(nil, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if got != nil {
				for _, app := range got.Applications {
					sort.Sort(app.Libraries)
				}
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_conanLockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "default name",
			filePath: "conan.lock",
			want:     true,
		},
		{
			name:     "name with prefix",
			filePath: "pkga_deps.lock",
			want:     false,
		},
		{
			name:     "txt",
			filePath: "test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			f, err := os.Create(filepath.Join(dir, tt.filePath))
			require.NoError(t, err)
			defer f.Close()

			fi, err := f.Stat()
			require.NoError(t, err)

			a := conanLockAnalyzer{}
			got := a.Required("", fi)
			assert.Equal(t, tt.want, got)
		})
	}
}
