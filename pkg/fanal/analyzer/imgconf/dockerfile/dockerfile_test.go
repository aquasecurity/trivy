package dockerfile

import (
	"bytes"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile/parser"
)

func Test_historyAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.ConfigAnalysisInput
		want    *analyzer.ConfigAnalysisResult
		wantErr bool
	}{
		{
			name: "happy path no policy failure",
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
							// this is fine, see https://github.com/aquasecurity/trivy-checks/pull/60 for details
							CreatedBy:  "/bin/sh -c #(nop) ADD file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /",
							EmptyLayer: false,
						},
						{
							CreatedBy:  `HEALTHCHECK &{["CMD-SHELL" "curl --fail http://localhost:3000 || exit 1"] "10s" "3s" "0s" '\x00'}`,
							EmptyLayer: false,
						},
						{
							CreatedBy:  `USER user`,
							EmptyLayer: true,
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
				},
			},
		},
		{
			name: "happy path with policy failure",
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
							CreatedBy:  "/bin/sh -c #(nop) ADD foo.txt /",
							EmptyLayer: false,
						},
						{
							CreatedBy:  `HEALTHCHECK &{["CMD-SHELL" "curl --fail http://localhost:3000 || exit 1"] "10s" "3s" "0s" '\x00'}`,
							EmptyLayer: false,
						},
						{
							CreatedBy:  `USER user`,
							EmptyLayer: true,
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
							Namespace: "builtin.dockerfile.DS005",
							Query:     "data.builtin.dockerfile.DS005.deny",
							Message:   "Consider using 'COPY foo.txt /' command instead of 'ADD foo.txt /'",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "DS-0005",
								Aliases:            []string{"AVD-DS-0005", "DS005", "use-copy-over-add"},
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
											Content:     "ADD foo.txt /",
											IsCause:     true,
											Truncated:   false,
											Highlighted: "\x1b[38;5;64mADD\x1b[0m foo.txt /",
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
			name: "happy path with buildkit instructions",
			input: analyzer.ConfigAnalysisInput{
				Config: &v1.ConfigFile{
					Config: v1.Config{
						Healthcheck: &v1.HealthConfig{
							Test:     []string{"CMD-SHELL", "curl --fail http://localhost:3000 || exit 1"},
							Interval: time.Second * 10,
							Timeout:  time.Second * 3,
						},
						User: "1002",
					},
					History: []v1.History{
						{
							CreatedBy:  "/bin/sh -c #(nop) ADD file:289c2fac17119508ced527225d445747cd177111b4a0018a6b04948ecb3b5e29 in / ",
							EmptyLayer: false,
						},
						{
							CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
							EmptyLayer: true,
						},
						{
							CreatedBy:  "ADD ./foo.txt /foo.txt # buildkit",
							EmptyLayer: false,
						},
						{
							CreatedBy:  "COPY ./foo /foo # buildkit",
							EmptyLayer: false,
						},
						{
							CreatedBy:  "RUN /bin/sh -c ls -hl /foo # buildkit",
							EmptyLayer: false,
						},
						{
							CreatedBy:  "USER root", // .Config.User takes precedence over this line
							EmptyLayer: true,
						},
						{
							CreatedBy:  `HEALTHCHECK &{["CMD-SHELL" "curl -sS 127.0.0.1 || exit 1"] "10s" "3s" "0s" '\x00'}`,
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
							Namespace: "builtin.dockerfile.DS005",
							Query:     "data.builtin.dockerfile.DS005.deny",
							Message:   "Consider using 'COPY ./foo.txt /foo.txt' command instead of 'ADD ./foo.txt /foo.txt'",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "DS-0005",
								Aliases:            []string{"AVD-DS-0005", "DS005", "use-copy-over-add"},
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
											Content:     "ADD ./foo.txt /foo.txt",
											IsCause:     true,
											Truncated:   false,
											Highlighted: "\x1b[38;5;64mADD\x1b[0m ./foo.txt /foo.txt",
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
			name: "happy path. Base layer is found",
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
							CreatedBy:  `/bin/sh -c #(nop)  CMD [\"/bin/sh\"]`,
							EmptyLayer: true,
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
								ID:                 "DS-0002",
								Aliases:            []string{"AVD-DS-0002", "DS002", "least-privilege-user"},
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
		{
			name: "DS016 check not detected",
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
							// duplicate command from another layer
							CreatedBy:  `/bin/sh -c #(nop) CMD [\"/bin/bash\"]`,
							EmptyLayer: true,
						},
						{
							CreatedBy: "/bin/sh -c #(nop) ADD file:e4d600fc4c9c293efe360be7b30ee96579925d1b4634c94332e2ec73f7d8eca1 in /",
						},
						{
							CreatedBy: `HEALTHCHECK &{["CMD-SHELL" "curl --fail http://localhost:3000 || exit 1"] "10s" "3s" "0s" '\x00'}`,
						},
						{
							CreatedBy:  `USER user`,
							EmptyLayer: true,
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
					FileType: types.Dockerfile,
					FilePath: "Dockerfile",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newHistoryAnalyzer(analyzer.ConfigAnalyzerOptions{})
			require.NoError(t, err)
			got, err := a.Analyze(t.Context(), tt.input)
			if tt.wantErr {
				require.Error(t, err)
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

func Test_ImageConfigToDockerfile(t *testing.T) {
	tests := []struct {
		name     string
		input    *v1.ConfigFile
		expected string
	}{
		{
			name: "run instruction with build args",
			input: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "RUN |1 pkg=curl /bin/sh -c apk add $pkg # buildkit",
					},
				},
			},
			expected: "RUN apk add $pkg\n",
		},
		{
			name: "healthcheck instruction with system's default shell",
			input: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "HEALTHCHECK &{[\"CMD-SHELL\" \"curl -f http://localhost/ || exit 1\"] \"5m0s\" \"3s\" \"1s\" \"5s\" '\\x03'}",
					},
				},
				Config: v1.Config{
					Healthcheck: &v1.HealthConfig{
						Test:        []string{"CMD-SHELL", "curl -f http://localhost/ || exit 1"},
						Interval:    time.Minute * 5,
						Timeout:     time.Second * 3,
						StartPeriod: time.Second * 1,
						Retries:     3,
					},
				},
			},
			expected: "HEALTHCHECK --interval=5m0s --timeout=3s --start-period=1s --retries=3 CMD curl -f http://localhost/ || exit 1\n",
		},
		{
			name: "healthcheck instruction exec arguments directly",
			input: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "HEALTHCHECK &{[\"CMD\" \"curl\" \"-f\" \"http://localhost/\" \"||\" \"exit 1\"] \"0s\" \"0s\" \"0s\" \"0s\" '\x03'}",
					},
				},
				Config: v1.Config{
					Healthcheck: &v1.HealthConfig{
						Test:    []string{"CMD", "curl", "-f", "http://localhost/", "||", "exit 1"},
						Retries: 3,
					},
				},
			},
			expected: "HEALTHCHECK --retries=3 CMD curl -f http://localhost/ || exit 1\n",
		},
		{
			name: "nop, no run instruction",
			input: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "/bin/sh -c #(nop)  ARG TAG=latest",
					},
				},
			},
			expected: "ARG TAG=latest\n",
		},
		{
			name: "buildkit metadata instructions",
			input: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "ARG TAG=latest",
					},
					{
						CreatedBy: "ENV TAG=latest",
					},
					{
						CreatedBy: "ENTRYPOINT [\"/bin/sh\" \"-c\" \"echo test\"]",
					},
				},
			},
			expected: `ARG TAG=latest
ENV TAG="latest"
ENTRYPOINT ["/bin/sh" "-c" "echo test"]
`,
		},
		{
			name: "remove backend-specific metadata suffixes",
			input: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "/bin/sh -c #(nop) COPY dir:3a024d8085bc39741a0a094a8e287a00a760975c7c2e6b5dc6c7d3174b7d1ab6 in ./files |inheritLabels=false",
					},
					{
						CreatedBy: "/bin/sh -c #(nop) ADD file:24d346633efc860b5011cefa5c0af73006e74e5dfb3c5c0e9cb0e90a927931e1 in readme |inheritLabels=false",
					},
					{
						CreatedBy: "/bin/sh -c #(nop) HEALTHCHECK NONE|unsetLabel=true|inheritLabels=false|force-mtime=10",
					},
					{
						CreatedBy: `/bin/sh -c #(nop) ENTRYPOINT ["/bin/sh"]|inheritLabels=false`,
					},
				},
			},
			expected: `COPY dir:3a024d8085bc39741a0a094a8e287a00a760975c7c2e6b5dc6c7d3174b7d1ab6 ./files
ADD file:24d346633efc860b5011cefa5c0af73006e74e5dfb3c5c0e9cb0e90a927931e1 readme
HEALTHCHECK NONE
ENTRYPOINT ["/bin/sh"]
`,
		},
		{
			name: "legacy env format",
			input: &v1.ConfigFile{
				History: []v1.History{
					{
						CreatedBy: "ENV TEST=foo bar",
					},
				},
			},
			expected: "ENV TEST=\"foo bar\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := imageConfigToDockerfile(tt.input)
			p := parser.NewParser(parser.WithStrict())
			_, err := p.Parse(t.Context(), bytes.NewReader(got), "Dockerfile")
			require.NoError(t, err)

			assert.Equal(t, tt.expected, string(got))
		})
	}
}
