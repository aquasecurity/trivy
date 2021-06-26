package docker_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/docker"
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
						Type:     types.Dockerfile,
						FilePath: "testdata/Dockerfile.deployment",
						Content: map[string]interface{}{
							"stages": map[string]interface{}{
								"foo": []interface{}{
									map[string]interface{}{
										"Cmd":       "from",
										"Flags":     []interface{}{},
										"JSON":      false,
										"Original":  "FROM foo",
										"Stage":     float64(0),
										"StartLine": float64(1),
										"EndLine":   float64(1),
										"SubCmd":    "",
										"Value":     []interface{}{"foo"},
									},
									map[string]interface{}{
										"Cmd":       "copy",
										"Flags":     []interface{}{},
										"JSON":      false,
										"Original":  "COPY . /",
										"Stage":     float64(0),
										"StartLine": float64(2),
										"EndLine":   float64(2),
										"SubCmd":    "",
										"Value":     []interface{}{".", "/"},
									},
									map[string]interface{}{
										"Cmd":       "run",
										"Flags":     []interface{}{},
										"JSON":      false,
										"Original":  "RUN echo hello",
										"Stage":     float64(0),
										"StartLine": float64(3),
										"EndLine":   float64(3),
										"SubCmd":    "",
										"Value": []interface{}{
											"echo hello",
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
			name:      "happy path with multi-stage",
			inputFile: "testdata/Dockerfile.multistage",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     types.Dockerfile,
						FilePath: "testdata/Dockerfile.multistage",
						Content: map[string]interface{}{
							"stages": map[string]interface{}{
								"foo AS build": []interface{}{
									map[string]interface{}{
										"Cmd":       "from",
										"Flags":     []interface{}{},
										"JSON":      false,
										"Original":  "FROM foo AS build",
										"Stage":     float64(0),
										"StartLine": float64(1),
										"EndLine":   float64(1),
										"SubCmd":    "",
										"Value":     []interface{}{"foo", "AS", "build"},
									},
									map[string]interface{}{
										"Cmd":       "copy",
										"Flags":     []interface{}{},
										"JSON":      false,
										"Original":  "COPY . /",
										"Stage":     float64(0),
										"StartLine": float64(2),
										"EndLine":   float64(2),
										"SubCmd":    "",
										"Value":     []interface{}{".", "/"},
									},
									map[string]interface{}{
										"Cmd":       "run",
										"Flags":     []interface{}{},
										"JSON":      false,
										"Original":  "RUN echo hello",
										"Stage":     float64(0),
										"StartLine": float64(3),
										"EndLine":   float64(3),
										"SubCmd":    "",
										"Value":     []interface{}{"echo hello"},
									},
								},
								"scratch ": []interface{}{
									map[string]interface{}{
										"Cmd":       "from",
										"Flags":     []interface{}{},
										"JSON":      false,
										"Original":  "FROM scratch ",
										"Stage":     float64(1),
										"StartLine": float64(5),
										"EndLine":   float64(5),
										"SubCmd":    "",
										"Value":     []interface{}{"scratch"},
									},
									map[string]interface{}{
										"Cmd":       "copy",
										"Flags":     []interface{}{"--from=build"},
										"JSON":      false,
										"Original":  "COPY --from=build /bar /bar",
										"Stage":     float64(1),
										"StartLine": float64(6),
										"EndLine":   float64(6),
										"SubCmd":    "",
										"Value":     []interface{}{"/bar", "/bar"},
									},
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
			wantErr:   "ENV must have two arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := docker.NewConfigAnalyzer(nil)
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
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
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
		{
			name:        "file pattern",
			filePattern: regexp.MustCompile(`foo*`),
			filePath:    "foo_file",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := docker.NewConfigAnalyzer(tt.filePattern)
			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dockerConfigAnalyzer_Type(t *testing.T) {
	s := docker.NewConfigAnalyzer(nil)
	want := analyzer.TypeDockerfile
	got := s.Type()
	assert.Equal(t, want, got)
}
