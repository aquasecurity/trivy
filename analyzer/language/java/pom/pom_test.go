package pom

import (
	"os"
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
)

func Test_pomAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		target    analyzer.AnalysisTarget
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "testdata/happy/pom.xml",
						Libraries: []types.Package{
							{
								Name:    "com.example:example",
								Version: "1.0.0",
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/broken/pom.xml",
			wantErr:   "xml decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := pomAnalyzer{}
			got, err := a.Analyze(nil, analyzer.AnalysisTarget{
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

func Test_pomAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "test/pom.xml",
			want:     true,
		},
		{
			name:     "no extension",
			filePath: "test/pom",
			want:     false,
		},
		{
			name:     "json",
			filePath: "test/pom.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pomAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
