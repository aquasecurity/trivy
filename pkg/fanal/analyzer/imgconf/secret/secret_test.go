package secret

import (
	"context"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_secretAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		config  *v1.ConfigFile
		want    *analyzer.ConfigAnalysisResult
		wantErr bool
	}{
		{
			name: "happy path",
			config: &v1.ConfigFile{
				Config: v1.Config{
					Env: []string{
						"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
						"secret=ghp_eifae6eigh3aeSah1shahd6oi1tague6vaey", // dummy token
					},
				},
			},
			want: &analyzer.ConfigAnalysisResult{
				Secret: &types.Secret{
					FilePath: "config.json",
					Findings: []types.SecretFinding{
						{
							RuleID:    "github-pat",
							Category:  "GitHub",
							Severity:  "CRITICAL",
							Title:     "GitHub Personal Access Token",
							StartLine: 12,
							EndLine:   12,
							Code: types.Code{
								Lines: []types.Line{
									{
										Number:      10,
										Content:     "  \"Env\": [",
										Highlighted: "  \"Env\": [",
									},
									{
										Number:      11,
										Content:     "  \"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",",
										Highlighted: "  \"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",",
									},
									{
										Number:      12,
										Content:     "  \"secret=****************************************\"",
										IsCause:     true,
										Highlighted: "  \"secret=****************************************\"",
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number:      13,
										Content:     "  ]",
										Highlighted: "  ]",
									},
								},
							},
							Match: "  \"secret=****************************************\"",
						},
					},
				},
			},
		},
		{
			name: "no secret",
			config: &v1.ConfigFile{
				Config: v1.Config{
					Env: []string{
						"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					},
				},
			},
			want: nil,
		},
		{
			name:   "nil config",
			config: nil,
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newSecretAnalyzer(analyzer.ConfigAnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.Analyze(context.Background(), analyzer.ConfigAnalysisInput{
				Config: tt.config,
			})
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
