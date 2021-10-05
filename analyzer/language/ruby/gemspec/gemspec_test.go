package gemspec

import (
	"io/ioutil"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_gemspecLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/multiple_licenses.gemspec",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GemSpec,
						FilePath: "testdata/multiple_licenses.gemspec",
						Libraries: []types.Package{
							{
								Name:     "test-unit",
								Version:  "3.3.7",
								License:  "Ruby, BSDL, PSFL",
								FilePath: "testdata/multiple_licenses.gemspec",
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
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := gemspecLibraryAnalyzer{}
			got, err := a.Analyze(analyzer.AnalysisTarget{
				FilePath: tt.inputFile,
				Content:  b,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
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
