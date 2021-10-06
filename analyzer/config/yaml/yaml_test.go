package yaml_test

import (
	"context"
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/yaml"
	"github.com/aquasecurity/fanal/types"
)

func Test_yamlConfigAnalyzer_Analyze(t *testing.T) {
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
			inputFile: "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     "yaml",
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
			name: "deny",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/deployment_deny.yaml",
			want: &analyzer.AnalysisResult{
				OS:           (*types.OS)(nil),
				PackageInfos: []types.PackageInfo(nil),
				Applications: []types.Application(nil), Configs: []types.Config{
					{
						Type:     "yaml",
						FilePath: "testdata/deployment_deny.yaml",
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
			name: "happy path using anchors",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/deny.rego"},
			},
			inputFile: "testdata/anchor.yaml",
			want: &analyzer.AnalysisResult{
				OS:           (*types.OS)(nil),
				PackageInfos: []types.PackageInfo(nil),
				Applications: []types.Application(nil),
				Configs: []types.Config{
					{
						Type:     "yaml",
						FilePath: "testdata/anchor.yaml",
						Content: map[string]interface{}{
							"default": map[string]interface{}{
								"line": "single line",
							},
							"fred": map[string]interface{}{
								"fred_name": "fred",
							},
							"john": map[string]interface{}{
								"john_name": "john",
							},
							"main": map[string]interface{}{
								"comment": "multi\nline\n",
								"line":    "single line",
								"name": map[string]interface{}{
									"fred_name": "fred",
									"john_name": "john",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple yaml",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/multiple.yaml",
			want: &analyzer.AnalysisResult{
				OS:           (*types.OS)(nil),
				PackageInfos: []types.PackageInfo(nil),
				Applications: []types.Application(nil),
				Configs: []types.Config{
					{
						Type:     "yaml",
						FilePath: "testdata/multiple.yaml",
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
					{
						Type:     "yaml",
						FilePath: "testdata/multiple.yaml",
						Content: map[string]interface{}{
							"apiVersion": "v1",
							"kind":       "Service",
							"metadata": map[string]interface{}{
								"name": "hello-kubernetes",
							},
							"spec": map[string]interface{}{
								"ports": []interface{}{map[string]interface{}{
									"port":       float64(80),
									"protocol":   "TCP",
									"targetPort": float64(8080),
								},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy with yaml which incompatible with json spec",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/deny.rego"},
			},
			inputFile: "testdata/incompatible_json.yaml",
			want: &analyzer.AnalysisResult{
				OS:           (*types.OS)(nil),
				PackageInfos: []types.PackageInfo(nil),
				Applications: []types.Application(nil),
				Configs: []types.Config{
					{
						Type:     "yaml",
						FilePath: "testdata/incompatible_json.yaml",
						Content: map[string]interface{}{
							"replacements": map[string]interface{}{
								"amd64": "64bit",
								"386":   "32bit",
								"arm":   "ARM",
							},
						},
					},
				},
			},
		},
		{
			name: "broken YAML",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/broken.yaml",
			wantErr:   "unmarshal yaml",
		},
		{
			name: "invalid circular references yaml",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/circular_references.yaml",
			wantErr:   "yaml: anchor 'circular' value contains itself",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := yaml.NewConfigAnalyzer(nil)
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisTarget{
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
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
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
		{
			name:        "file pattern",
			filePattern: regexp.MustCompile(`foo*`),
			filePath:    "foo_file",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := yaml.NewConfigAnalyzer(tt.filePattern)

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yamlConfigAnalyzer_Type(t *testing.T) {
	s := yaml.NewConfigAnalyzer(nil)

	want := analyzer.TypeYaml
	got := s.Type()
	assert.Equal(t, want, got)
}
