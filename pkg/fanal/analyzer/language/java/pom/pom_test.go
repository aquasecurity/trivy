package pom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

func Test_pomAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputDir  string
		inputFile string
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
						Packages: types.Packages{
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000001",
								Name:         "com.example:example",
								Version:      "1.0.0",
								Licenses:     []string{"Apache-2.0"},
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"3ff14136-e09f-4df9-80ea-000000000002",
								},
							},
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000002",
								Name:         "com.example:example-api",
								Version:      "2.0.0",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   32,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy dir path",
			inputDir:  "testdata/happy",
			inputFile: "pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "pom.xml",
						Packages: types.Packages{
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000001",
								Name:         "com.example:example",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								Licenses:     []string{"Apache-2.0"},
								DependsOn: []string{
									"3ff14136-e09f-4df9-80ea-000000000002",
								},
							},
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000002",
								Name:         "com.example:example-api",
								Version:      "2.0.0",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   32,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for maven-invoker-plugin integration tests",
			inputFile: "testdata/mark-as-dev/src/it/example/pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "testdata/mark-as-dev/src/it/example/pom.xml",
						Packages: types.Packages{
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000001",
								Name:         "com.example:example",
								Version:      "1.0.0",
								Licenses:     []string{"Apache-2.0"},
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"3ff14136-e09f-4df9-80ea-000000000002",
								},
								Dev: true,
							},
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000002",
								Name:         "com.example:example-api",
								Version:      "@example.version@",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   32,
									},
								},
								Dev: true,
							},
						},
					},
				},
			},
		},
		{
			name:      "unsupported requirement",
			inputFile: "testdata/requirements/pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "testdata/requirements/pom.xml",
						Packages: types.Packages{
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000001",
								Name:         "com.example:example",
								Version:      "2.0.0",
								Licenses:     []string{"Apache-2.0"},
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"3ff14136-e09f-4df9-80ea-000000000002",
								},
							},
							{
								ID:           "3ff14136-e09f-4df9-80ea-000000000002",
								Name:         "org.example:example-api",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 21,
										EndLine:   25,
									},
								},
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
		{
			name:      "sad dir path",
			inputDir:  "testdata/broken",
			inputFile: "pom.xml",
			wantErr:   "xml decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			f, err := os.Open(filepath.Join(tt.inputDir, tt.inputFile))
			require.NoError(t, err)
			defer f.Close()

			a := pomAnalyzer{}
			got, err := a.Analyze(nil, analyzer.AnalysisInput{
				Dir:      tt.inputDir,
				FilePath: tt.inputFile,
				Content:  f,
				Options: analyzer.AnalysisOptions{
					Offline: true,
				},
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
