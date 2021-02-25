package toml

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func Test_tomlConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/deployment.toml",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.TOML,
						FilePath: "testdata/deployment.toml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "hello-kubernetes",
							},
							"spec": map[string]interface{}{
								"replicas": int64(3),
							},
						},
					},
				},
			},
		},
		{
			name:      "broken TOML",
			inputFile: "testdata/broken.toml",
			wantErr:   "unmarshal toml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := tomlConfigAnalyzer{
				parser: &toml.Parser{},
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

func Test_tomlConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "toml",
			filePath: "deployment.toml",
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
			a := tomlConfigAnalyzer{
				parser: &toml.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
