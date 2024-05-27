package pip

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pipAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		venv    string
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path with licenses from venv",
			dir:  "testdata/happy",
			venv: "testdata",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pip,
						FilePath: "requirements.txt",
						Packages: types.Packages{
							{
								Name:    "click",
								Version: "8.0.0",
								Locations: []types.Location{
									{
										StartLine: 1,
										EndLine:   1,
									},
								},
								Licenses: []string{
									"BSD License",
								},
							},
							{
								Name:    "Flask",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 2,
										EndLine:   2,
									},
								},
								Licenses: []string{
									"BSD License",
								},
							},
							{
								Name:    "itsdangerous",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 3,
										EndLine:   3,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with not related filename",
			dir:  "testdata/empty",
			want: &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.venv != "" {
				t.Setenv("VIRTUAL_ENV", tt.venv)
			}
			a, err := newPipLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pipAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "test/requirements.txt",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "a/b/c/d/test.sum",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pipLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
