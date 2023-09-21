package nuget

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_nugetibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		env  map[string]string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path config file.",
			dir:  "testdata/config",
			env: map[string]string{
				"HOME": "testdata/repository",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "packages.config",
						Libraries: types.Packages{
							{
								Name:    "Microsoft.AspNet.WebApi",
								Version: "5.2.2",
							},
							{
								Name:    "Newtonsoft.Json",
								Version: "6.0.4",
							},
						},
					},
				},
			},
		},
		{
			name: "happy path lock file.",
			dir:  "testdata/lock",
			env: map[string]string{
				"HOME": "testdata/repository",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "packages.lock.json",
						Libraries: types.Packages{
							{
								ID:      "Newtonsoft.Json@12.0.3",
								Name:    "Newtonsoft.Json",
								Version: "12.0.3",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:      "NuGet.Frameworks@5.7.0",
								Name:    "NuGet.Frameworks",
								Version: "5.7.0",
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   19,
									},
								},
								DependsOn: []string{"Newtonsoft.Json@12.0.3"},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path lock file. `NUGET_PACKAGES` env is used",
			dir:  "testdata/lock",
			env: map[string]string{
				"NUGET_PACKAGES": "testdata/repository/.nuget/packages",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "packages.lock.json",
						Libraries: types.Packages{
							{
								ID:      "Newtonsoft.Json@12.0.3",
								Name:    "Newtonsoft.Json",
								Version: "12.0.3",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:      "NuGet.Frameworks@5.7.0",
								Name:    "NuGet.Frameworks",
								Version: "5.7.0",
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   19,
									},
								},
								DependsOn: []string{"Newtonsoft.Json@12.0.3"},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path lock file. `.nuget` directory doesn't exist",
			dir:  "testdata/lock",
			env: map[string]string{
				"HOME": "testdata/invalid",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "packages.lock.json",
						Libraries: types.Packages{
							{
								ID:      "Newtonsoft.Json@12.0.3",
								Name:    "Newtonsoft.Json",
								Version: "12.0.3",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
								},
							},
							{
								ID:      "NuGet.Frameworks@5.7.0",
								Name:    "NuGet.Frameworks",
								Version: "5.7.0",
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   19,
									},
								},
								DependsOn: []string{"Newtonsoft.Json@12.0.3"},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for env, path := range tt.env {
				t.Setenv(env, path)
			}
			a, err := newNugetLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_nugetLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "config",
			filePath: "test/packages.config",
			want:     true,
		},
		{
			name:     "lock",
			filePath: "test/packages.lock.json",
			want:     true,
		},
		{
			name:     "zip",
			filePath: "test.zip",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := nugetLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
