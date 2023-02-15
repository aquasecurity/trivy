package yarn

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_yarnLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy_yarn.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "testdata/happy_yarn.lock",
						Libraries: []types.Package{
							{
								ID:      "asap@2.0.6",
								Name:    "asap",
								Version: "2.0.6",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
							{
								ID:      "jquery@3.4.1",
								Name:    "jquery",
								Version: "3.4.1",
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   13,
									},
								},
							},
							{
								ID:      "promise@8.0.3",
								Name:    "promise",
								Version: "8.0.3",
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"asap@2.0.6",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/wrong_yarn.lock",
			wantErr:   "unable to parse yarn.lock",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := yarnLibraryAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
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

func Test_nodePkgLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "yarn.lock",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "npm/package.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := yarnLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
