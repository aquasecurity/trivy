package json

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
			inputFile: filepath.Join("testdata", "deployment.json"),
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "json",
							Path: filepath.Join("testdata", "deployment.json"),
							Content: []byte(`{
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"metadata": {
		"name": "hello-kubernetes"
	},
	"spec": {
		"replicas": 3
	}
}
`),
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
			inputFile: filepath.Join("testdata", "deployment_deny.json"),
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "json",
							Path: filepath.Join("testdata", "deployment_deny.json"),
							Content: []byte(`{
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"metadata": {
		"name": "hello-kubernetes"
	},
	"spec": {
		"replicas": 4
	}
}
`),
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
			inputFile: filepath.Join("testdata", "array.json"),
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "json",
							Path: filepath.Join("testdata", "array.json"),
							Content: []byte(`[
	{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "hello-kubernetes"
		},
		"spec": {
			"replicas": 4
		}
	},
	{
		"apiVersion": "apps/v2",
		"kind": "Deployment",
		"metadata": {
			"name": "hello-kubernetes"
		},
		"spec": {
			"replicas": 5
		}
	}
]
`),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			s := jsonConfigAnalyzer{}

			ctx := context.Background()
			got, err := s.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
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
		{
			name:     "npm json",
			filePath: "package-lock.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := jsonConfigAnalyzer{}

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_jsonConfigAnalyzer_Type(t *testing.T) {
	s := jsonConfigAnalyzer{}

	want := analyzer.TypeJSON
	got := s.Type()
	assert.Equal(t, want, got)
}
