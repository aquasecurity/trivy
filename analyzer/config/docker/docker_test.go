package docker

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func Test_dockerConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.Dockerfile,
						FilePath: "testdata/Dockerfile.deployment",
						Content: []interface{}{
							[]interface{}{
								map[string]interface{}{
									"Cmd":    "from",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{},
									"Value":  []interface{}{"foo"},
								},
								map[string]interface{}{
									"Cmd":    "copy",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{},
									"Value":  []interface{}{".", "/"},
								},
								map[string]interface{}{
									"Cmd":    "run",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{},
									"Value":  []interface{}{"echo hello"},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path with multi-stage",
			inputFile: "testdata/Dockerfile.multistage",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.Dockerfile,
						FilePath: "testdata/Dockerfile.multistage",
						Content: []interface{}{
							[]interface{}{
								map[string]interface{}{
									"Cmd":    "from",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{},
									"Value":  []interface{}{"foo", "AS", "build"},
								},
								map[string]interface{}{
									"Cmd":    "copy",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{},
									"Value":  []interface{}{".", "/"},
								},
								map[string]interface{}{
									"Cmd":    "run",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{},
									"Value":  []interface{}{"echo hello"},
								},
								map[string]interface{}{
									"Cmd":    "from",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{},
									"Value":  []interface{}{"scratch"},
								},
								map[string]interface{}{
									"Cmd":    "copy",
									"SubCmd": "",
									"JSON":   false,
									"Flags":  []interface{}{"--from=build"},
									"Value":  []interface{}{"/bar", "/bar"},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "broken Docker: env no value",
			inputFile: "testdata/Dockerfile.broken",
			wantErr:   "parse dockerfile: ENV must have two arguments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := dockerConfigAnalyzer{
				parser: &docker.Parser{},
			}

			got, err := a.Analyze(analyzer.AnalysisTarget{
				FilePath: tt.inputFile,
				Content:  b,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dockerConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "dockerfile",
			filePath: "dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile",
			filePath: "Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile with ext",
			filePath: "Dockerfile.build",
			want:     true,
		},
		{
			name:     "dockerfile as ext",
			filePath: "build.dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile in dir",
			filePath: "docker/Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile as prefix",
			filePath: "Dockerfilebuild",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix",
			filePath: "buildDockerfile",
			want:     false,
		},
		{
			name:     "Dockerfile as prefix with ext",
			filePath: "Dockerfilebuild.sh",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix with ext",
			filePath: "buildDockerfile.sh",
			want:     false,
		},
		{
			name:     "json",
			filePath: "deployment.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := dockerConfigAnalyzer{
				parser: &docker.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dockerConfigAnalyzer_Type(t *testing.T) {
	want := analyzer.TypeDockerfile
	a := dockerConfigAnalyzer{
		parser: &docker.Parser{},
	}
	got := a.Type()
	assert.Equal(t, want, got)
}
