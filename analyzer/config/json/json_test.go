package json

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func Test_jsonConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/deployment.json",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.JSON,
						FilePath: "testdata/deployment.json",
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
			name:      "happy path: json array",
			inputFile: "testdata/array.json",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.JSON,
						FilePath: "testdata/array.json",
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
								"apiVersion": "apps/v2",
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
		},
		{
			name:      "broken JSON",
			inputFile: "testdata/broken.json",
			wantErr:   "unmarshal json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := jsonConfigAnalyzer{
				parser: &json.Parser{},
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

func Test_jsonConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "json",
			filePath: "deployment.json",
			want:     true,
		},
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := jsonConfigAnalyzer{
				parser: &json.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_jsonConfigAnalyzer_Type(t *testing.T) {
	want := analyzer.TypeJSON
	a := jsonConfigAnalyzer{
		parser: &json.Parser{},
	}
	got := a.Type()
	assert.Equal(t, want, got)
}
