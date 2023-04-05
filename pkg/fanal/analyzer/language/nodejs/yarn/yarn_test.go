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
		name    string
		dir     string
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: []types.Package{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
							{
								ID:       "js-tokens@4.0.0",
								Name:     "js-tokens",
								Version:  "4.0.0",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   13,
									},
								},
							},
							{
								ID:       "loose-envify@1.4.0",
								Name:     "loose-envify",
								Version:  "1.4.0",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"js-tokens@4.0.0",
								},
							},
							{
								ID:       "object-assign@4.1.1",
								Name:     "object-assign",
								Version:  "4.1.1",
								Indirect: true,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   25,
									},
								},
							},
							{
								ID:      "scheduler@0.13.6",
								Name:    "scheduler",
								Version: "0.13.6",
								Locations: []types.Location{
									{
										StartLine: 41,
										EndLine:   47,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no package.json",
			dir:  "testdata/no-packagejson",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: []types.Package{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
							{
								ID:      "js-tokens@4.0.0",
								Name:    "js-tokens",
								Version: "4.0.0",
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   13,
									},
								},
							},
							{
								ID:      "loose-envify@1.4.0",
								Name:    "loose-envify",
								Version: "1.4.0",
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"js-tokens@4.0.0",
								},
							},
							{
								ID:      "object-assign@4.1.1",
								Name:    "object-assign",
								Version: "4.1.1",
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   25,
									},
								},
							},
							{
								ID:      "prop-types@15.7.2",
								Name:    "prop-types",
								Version: "15.7.2",
								Locations: []types.Location{
									{
										StartLine: 27,
										EndLine:   34,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
									"react-is@16.13.1",
								},
							},
							{
								ID:      "react-is@16.13.1",
								Name:    "react-is",
								Version: "16.13.1",
								Locations: []types.Location{
									{
										StartLine: 36,
										EndLine:   39,
									},
								},
							},
							{
								ID:      "scheduler@0.13.6",
								Name:    "scheduler",
								Version: "0.13.6",
								Locations: []types.Location{
									{
										StartLine: 41,
										EndLine:   47,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "wrong package.json",
			dir:  "testdata/wrong-packagejson",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Libraries: []types.Package{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
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
			name:    "sad path",
			dir:     "testdata/sad",
			wantErr: "failed to parse yarn.lock",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
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
			name:     "happy path yarn.lock",
			filePath: "test/yarn.lock",
			want:     true,
		},
		{
			name:     "happy path package.json",
			filePath: "test/package.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "test/package-lock.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := yarnAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
