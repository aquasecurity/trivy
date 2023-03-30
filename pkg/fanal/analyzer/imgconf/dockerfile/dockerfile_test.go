package dockerfile

import (
	"context"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_historyAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.ConfigAnalysisInput
		want    *analyzer.ConfigAnalysisResult
		wantErr bool
	}{
		{
			name: "happy",
			input: analyzer.ConfigAnalysisInput{
				Config: &v1.ConfigFile{
					Config: v1.Config{
						Healthcheck: &v1.HealthConfig{
							Test:     []string{"CMD-SHELL", "curl --fail http://localhost:3000 || exit 1"},
							Interval: time.Second * 10,
							Timeout:  time.Second * 3,
						},
					},
					History: []v1.History{
						{
							CreatedBy:  "/bin/sh -c #(nop) ADD file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /",
							EmptyLayer: false,
						},
						{
							CreatedBy:  `HEALTHCHECK &{["CMD-SHELL" "curl --fail http://localhost:3000 || exit 1"] "10s" "3s" "0s" '\x00'}`,
							EmptyLayer: false,
						},
						{
							CreatedBy:  `/bin/sh -c #(nop)  CMD [\"/bin/sh\"]`,
							EmptyLayer: true,
						},
					},
				},
			},
			want: &analyzer.ConfigAnalysisResult{
				Misconfiguration: &types.Misconfiguration{
					FileType: "dockerfile",
					FilePath: "Dockerfile",
					Failures: types.MisconfResults{
						types.MisconfResult{
							Namespace: "builtin.dockerfile.DS002",
							Query:     "data.builtin.dockerfile.DS002.deny",
							Message:   "Specify at least 1 USER command in Dockerfile with non-root user as argument",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "DS002",
								AVDID:              "AVD-DS-0002",
								Type:               "Dockerfile Security Check",
								Title:              "Image user should not be 'root'",
								Description:        "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
								Severity:           "HIGH",
								RecommendedActions: "Add 'USER <non root user name>' line to the Dockerfile",
								References: []string{
									"https://docs.docker." +
										"com/develop/develop-images/dockerfile_best-practices/",
								},
							},
							CauseMetadata: types.CauseMetadata{
								Provider: "Dockerfile",
								Service:  "general",
							},
						},
						types.MisconfResult{
							Namespace: "builtin.dockerfile.DS005",
							Query:     "data.builtin.dockerfile.DS005.deny",
							Message:   "Consider using 'COPY file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /' command instead of 'ADD file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /'",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "DS005",
								AVDID:              "AVD-DS-0005",
								Type:               "Dockerfile Security Check",
								Title:              "ADD instead of COPY",
								Description:        "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
								Severity:           "LOW",
								RecommendedActions: "Use COPY instead of ADD",
								References:         []string{"https://docs.docker.com/engine/reference/builder/#add"},
							},
							CauseMetadata: types.CauseMetadata{
								Provider:  "Dockerfile",
								Service:   "general",
								StartLine: 1,
								EndLine:   1,
								Code: types.Code{
									Lines: []types.Line{
										{
											Number:      1,
											Content:     "ADD file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /",
											IsCause:     true,
											Truncated:   false,
											Highlighted: "\x1b[38;5;64mADD\x1b[0m file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /",
											FirstCause:  true,
											LastCause:   true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "nil config",
			input: analyzer.ConfigAnalysisInput{
				Config: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newHistoryAnalyzer(analyzer.ConfigAnalyzerOptions{})
			require.NoError(t, err)
			got, err := a.Analyze(context.Background(), tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			if got != nil && got.Misconfiguration != nil {
				got.Misconfiguration.Successes = nil // Not compare successes in this test
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
