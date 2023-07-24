package nuget

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_nugetibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path config file",
			inputFile: "testdata/packages.config",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "testdata/packages.config",
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
			name:      "happy path lock file",
			inputFile: "testdata/packages.lock.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "testdata/packages.lock.json",
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
		{
			name:      "sad path",
			inputFile: "testdata/invalid.txt",
			wantErr:   "NuGet analysis error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := nugetLibraryAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			// Sort libraries for consistency
			for _, app := range got.Applications {
				sort.Sort(app.Libraries)
			}

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
