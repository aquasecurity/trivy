package hcl_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/hcl"
	"github.com/aquasecurity/fanal/types"
)

func TestConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "HCL1: happy path",
			inputFile: "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     types.HCL,
						FilePath: "testdata/deployment.hcl1",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": []map[string]interface{}{
								{
									"name": "hello-kubernetes",
								},
							},
							"spec": []map[string]interface{}{
								{
									"replicas": 3,
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "HCL1: broken",
			inputFile: "testdata/broken.hcl1",
			wantErr:   "unmarshal hcl",
		},
		{
			name:      "HCL2: happy path",
			inputFile: "testdata/deployment.hcl2",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     types.HCL,
						FilePath: "testdata/deployment.hcl2",
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
			name:      "HCL2: broken",
			inputFile: "testdata/broken.hcl2",
			wantErr:   "unable to parse HCL2",
		},
		{
			name:      "HCL2: deprecated",
			inputFile: "testdata/deprecated.hcl",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     types.HCL,
						FilePath: "testdata/deprecated.hcl",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": []map[string]interface{}{
								{
									"name": "hello-kubernetes",
								},
							},
							"spec": []map[string]interface{}{
								{
									"replicas": int(3),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := hcl.NewConfigAnalyzer(nil)
			require.NoError(t, err)

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

func TestConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
	}{
		{
			name:     "hcl",
			filePath: "deployment.hcl",
			want:     true,
		},
		{
			name:     "hcl1",
			filePath: "deployment.hcl1",
			want:     true,
		},
		{
			name:     "hcl2",
			filePath: "deployment.hcl2",
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
			s := hcl.NewConfigAnalyzer(tt.filePattern)
			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
func TestConfigAnalyzer_Type(t *testing.T) {
	s := hcl.NewConfigAnalyzer(nil)
	want := analyzer.TypeHCL
	got := s.Type()
	assert.Equal(t, want, got)
}
