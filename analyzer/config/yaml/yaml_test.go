package yaml

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func Test_yamlConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.YAML,
						FilePath: "testdata/deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "hello-kubernetes",
							},
							"spec": map[string]interface{}{
								"replicas": float64(3),
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path using anchors",
			inputFile: "testdata/anchor.yaml",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.YAML,
						FilePath: "testdata/anchor.yaml",
						Content: map[string]interface{}{
							"default": map[string]interface{}{
								"line": "single line",
							},
							"john": map[string]interface{}{
								"john_name": "john",
							},
							"fred": map[string]interface{}{
								"fred_name": "fred",
							},
							"main": map[string]interface{}{
								"line": "single line",
								"name": map[string]interface{}{
									"john_name": "john",
									"fred_name": "fred",
								},
								"comment": "multi\nline\n",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path using multiple yaml",
			inputFile: "testdata/multiple.yaml",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.YAML,
						FilePath: "testdata/multiple.yaml",
						Content: []interface{}{
							map[string]interface{}{
								"apiVersion": "apps/v1",
								"kind":       "Deployment",
								"metadata": map[string]interface{}{
									"name": "hello-kubernetes",
								},
								"spec": map[string]interface{}{
									"replicas": float64(3),
								},
							},
							map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Service",
								"metadata": map[string]interface{}{
									"name": "hello-kubernetes",
								},
								"spec": map[string]interface{}{
									"ports": []interface{}{
										map[string]interface{}{
											"protocol":   "TCP",
											"port":       float64(80),
											"targetPort": float64(8080),
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
			name:      "broken YAML",
			inputFile: "testdata/broken.yaml",
			wantErr:   "unmarshal yaml",
		},
		{
			name:      "invalid circular references yaml",
			inputFile: "testdata/circular_references.yaml",
			wantErr:   "yaml: anchor 'circular' value contains itself",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := yamlConfigAnalyzer{
				parser: &yaml.Parser{},
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

func Test_yamlConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     true,
		},
		{
			name:     "yml",
			filePath: "deployment.yml",
			want:     true,
		},
		{
			name:     "json",
			filePath: "deployment.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := yamlConfigAnalyzer{
				parser: &yaml.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
