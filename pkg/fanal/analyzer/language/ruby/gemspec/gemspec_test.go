package gemspec

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gemspecLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name            string
		inputFile       string
		includeChecksum bool
		want            *analyzer.AnalysisResult
		wantErr         string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/multiple_licenses.gemspec",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GemSpec,
						FilePath: "testdata/multiple_licenses.gemspec",
						Packages: types.Packages{
							{
								Name:    "test-unit",
								Version: "3.3.7",
								Licenses: []string{
									"Ruby",
									"BSDL",
									"PSFL",
								},
								FilePath: "testdata/multiple_licenses.gemspec",
							},
						},
					},
				},
			},
		},
		{
			name:            "happy path with checksum",
			inputFile:       "testdata/multiple_licenses.gemspec",
			includeChecksum: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GemSpec,
						FilePath: "testdata/multiple_licenses.gemspec",
						Packages: types.Packages{
							{
								Name:    "test-unit",
								Version: "3.3.7",
								Licenses: []string{
									"Ruby",
									"BSDL",
									"PSFL",
								},
								FilePath: "testdata/multiple_licenses.gemspec",
								Digest:   "sha1:6ba7904180fad7e09f224cd3e4d449ea53401fb9",
							},
						},
					},
				},
			},
		},
		{
			name:      "empty name",
			inputFile: "testdata/empty_name.gemspec",
			want:      nil,
			wantErr:   "failed to parse",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := gemspecLibraryAnalyzer{}
			ctx := t.Context()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
				Options:  analyzer.AnalysisOptions{FileChecksum: tt.includeChecksum},
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_gemspecLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "with default",
			filePath: "usr/ank/specifications/default/ank.gemspec",
			want:     true,
		},
		{
			name:     "without default",
			filePath: "usr/ank/specifications/ank.gemspec",
			want:     true,
		},
		{
			name:     "without dot",
			filePath: "usr/ank/specifications/ankgemspec",
			want:     false,
		},
		{
			name:     "source gemspec",
			filePath: "/localtRepo/default/ank.gemspec",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gemspecLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
