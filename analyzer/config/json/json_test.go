package json_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/json"
	"github.com/aquasecurity/fanal/types"
)

func Test_jsonConfigAnalyzer_Analyze(t *testing.T) {
	type args struct {
		namespaces  []string
		policyPaths []string
	}
	tests := []struct {
		name      string
		args      args
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name: "happy path",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/deployment.json",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     "json",
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
			name: "deny",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/deployment_deny.json",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     "json",
						FilePath: "testdata/deployment_deny.json",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "hello-kubernetes",
							},
							"spec": map[string]interface{}{
								"replicas": float64(4),
							},
						},
					},
				},
			},
		},
		{
			name: "json array",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/array.json",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     "json",
						FilePath: "testdata/array.json",
						Content: []interface{}{map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "hello-kubernetes",
							},
							"spec": map[string]interface{}{
								"replicas": float64(4),
							},
						},
							map[string]interface{}{
								"apiVersion": "apps/v2",
								"kind":       "Deployment",
								"metadata": map[string]interface{}{
									"name": "hello-kubernetes",
								},
								"spec": map[string]interface{}{
									"replicas": float64(5),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "broken JSON",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/broken.json",
			wantErr:   "unable to parse JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			s := json.NewConfigAnalyzer(nil)

			got, err := s.Analyze(analyzer.AnalysisTarget{
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
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
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
		{
			name:     "npm json",
			filePath: "package-lock.json",
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
			s := json.NewConfigAnalyzer(tt.filePattern)

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_jsonConfigAnalyzer_Type(t *testing.T) {
	s := json.NewConfigAnalyzer(nil)

	want := analyzer.TypeJSON
	got := s.Type()
	assert.Equal(t, want, got)
}
