package poetry

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_poetryLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Poetry,
						FilePath: "testdata/happy.lock",
						Libraries: []types.Package{
							{
								ID:      "click@8.1.3",
								Name:    "click",
								Version: "8.1.3",
								DependsOn: []string{
									"colorama@0.4.6",
								},
							},
							{
								ID:      "colorama@0.4.6",
								Name:    "colorama",
								Version: "0.4.6",
							},
							{
								ID:      "flask@1.0.3",
								Name:    "flask",
								Version: "1.0.3",
								DependsOn: []string{
									"click@8.1.3",
									"itsdangerous@2.1.2",
									"jinja2@3.1.2",
									"werkzeug@2.2.3",
								},
							},
							{
								ID:      "itsdangerous@2.1.2",
								Name:    "itsdangerous",
								Version: "2.1.2",
							},
							{
								ID:      "jinja2@3.1.2",
								Name:    "jinja2",
								Version: "3.1.2",
								DependsOn: []string{
									"markupsafe@2.1.2",
								},
							},
							{
								ID:      "markupsafe@2.1.2",
								Name:    "markupsafe",
								Version: "2.1.2",
							},
							{
								ID:      "werkzeug@2.2.3",
								Name:    "werkzeug",
								Version: "2.2.3",
								DependsOn: []string{
									"markupsafe@2.1.2",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "wrong path",
			inputFile: "testdata/wrong.lock",
			wantErr:   "unable to parse poetry.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer func() { _ = f.Close() }()

			a := poetryLibraryAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
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
