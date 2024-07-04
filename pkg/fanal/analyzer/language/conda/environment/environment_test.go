package environment

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_environmentAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/environment.yaml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.CondaEnv,
						FilePath: "testdata/environment.yaml",
						Packages: types.Packages{
							{
								Name: "_libgcc_mutex",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
									},
								},
							},
							{
								Name:    "_openmp_mutex",
								Version: "5.1",
								Locations: []types.Location{
									{
										StartLine: 6,
										EndLine:   6,
									},
								},
							},
							{
								Name:    "blas",
								Version: "1.0",
								Locations: []types.Location{
									{
										StartLine: 7,
										EndLine:   7,
									},
								},
							},
							{
								Name:    "bzip2",
								Version: "1.0.8",
								Locations: []types.Location{
									{
										StartLine: 8,
										EndLine:   8,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path with licenses",
			inputFile: "testdata/environment-with-licenses.yaml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.CondaEnv,
						FilePath: "testdata/environment-with-licenses.yaml",
						Packages: types.Packages{
							{
								Name: "_libgcc_mutex",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
									},
								},
							},
							{
								Name:    "_openmp_mutex",
								Version: "5.1",
								Locations: []types.Location{
									{
										StartLine: 6,
										EndLine:   6,
									},
								},
								Licenses: []string{
									"BSD-3-Clause",
								},
							},
							{
								Name:    "blas",
								Version: "1.0",
								Locations: []types.Location{
									{
										StartLine: 7,
										EndLine:   7,
									},
								},
							},
							{
								Name:    "bzip2",
								Version: "1.0.8",
								Locations: []types.Location{
									{
										StartLine: 8,
										EndLine:   8,
									},
								},
								Licenses: []string{
									"bzip2-1.0.8",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty.yaml",
		},
		{
			name:      "invalid",
			inputFile: "testdata/invalid.yaml",
			wantErr:   "unable to parse environment.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := environmentAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_environmentAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path `yaml`",
			filePath: "foo/environment.yaml",
			want:     true,
		},
		{
			name:     "happy path `yml`",
			filePath: "bar/environment.yaml",
			want:     true,
		},
		{
			name:     "sad path `json` ",
			filePath: "environment.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := environmentAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
