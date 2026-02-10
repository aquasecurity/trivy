package pylock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pylockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   bool
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/pylock.toml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PyLock,
						FilePath: "testdata/happy/pylock.toml",
						Packages: types.Packages{
							{
								ID:      "certifi@2025.1.31",
								Name:    "certifi",
								Version: "2025.1.31",
							},
							{
								ID:      "charset-normalizer@3.4.1",
								Name:    "charset-normalizer",
								Version: "3.4.1",
							},
							{
								ID:      "idna@3.10",
								Name:    "idna",
								Version: "3.10",
							},
							{
								ID:      "requests@2.32.3",
								Name:    "requests",
								Version: "2.32.3",
								DependsOn: []string{
									"certifi@2025.1.31",
									"charset-normalizer@3.4.1",
									"idna@3.10",
									"urllib3@2.3.0",
								},
							},
							{
								ID:      "urllib3@2.3.0",
								Name:    "urllib3",
								Version: "2.3.0",
							},
						},
					},
				},
			},
		},
		{
			name:      "broken file",
			inputFile: "testdata/broken/pylock.toml",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := pylockAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pylockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "pylock.toml",
			want:     true,
		},
		{
			name:     "nested path",
			filePath: "some/dir/pylock.toml",
			want:     true,
		},
		{
			name:     "wrong file",
			filePath: "requirements.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pylockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
