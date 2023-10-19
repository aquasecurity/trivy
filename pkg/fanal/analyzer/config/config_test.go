package config_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

func TestAnalyzer_PostAnalyze(t *testing.T) {
	type fields struct {
		typ        analyzer.Type
		newScanner config.NewScanner
		opts       analyzer.AnalyzerOptions
	}
	tests := []struct {
		name    string
		fields  fields
		dir     string
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "dockerfile",
			fields: fields{
				typ:        analyzer.TypeDockerfile,
				newScanner: misconf.NewDockerfileScanner,
				opts: analyzer.AnalyzerOptions{
					MisconfScannerOption: misconf.ScannerOption{
						Namespaces:              []string{"user"},
						PolicyPaths:             []string{"testdata/rego"},
						DisableEmbeddedPolicies: true,
					},
				},
			},
			dir: "testdata/src",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Dockerfile,
						FilePath: "Dockerfile",
						Successes: types.MisconfResults{
							types.MisconfResult{
								Namespace: "user.something",
								Query:     "data.user.something.deny",
								PolicyMetadata: types.PolicyMetadata{
									ID:                 "TEST001",
									AVDID:              "AVD-TEST-0001",
									Type:               "Dockerfile Security Check",
									Title:              "Test policy",
									Description:        "This is a test policy.",
									Severity:           "LOW",
									RecommendedActions: "Have a cup of tea.",
									References:         []string{"https://trivy.dev/"},
								},
								CauseMetadata: types.CauseMetadata{
									Provider: "Generic",
									Service:  "general",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "non-existent dir",
			fields: fields{
				typ:        analyzer.TypeDockerfile,
				newScanner: misconf.NewDockerfileScanner,
				opts: analyzer.AnalyzerOptions{
					MisconfScannerOption: misconf.ScannerOption{
						Namespaces:              []string{"user"},
						PolicyPaths:             []string{"testdata/rego"},
						DisableEmbeddedPolicies: true,
					},
				},
			},
			dir:     "testdata/non-existent",
			wantErr: testutil.ErrNotExist,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := config.NewAnalyzer(tt.fields.typ, 0, tt.fields.newScanner, tt.fields.opts)
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
