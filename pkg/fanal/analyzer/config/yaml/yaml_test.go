package yaml

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
				policyPaths: []string{filepath.Join("..", "testdata", "kubernetes.rego")},
			},
			inputFile: filepath.Join("testdata", "deployment.yaml"),
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "yaml",
							Path: filepath.Join("testdata", "deployment.yaml"),
							Content: []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-kubernetes
spec:
  replicas: 3
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
				policyPaths: []string{filepath.Join("..", "testdata", "kubernetes.rego")},
			},
			inputFile: filepath.Join("testdata", "deployment_deny.yaml"),
			want: &analyzer.AnalysisResult{
				OS:           (*types.OS)(nil),
				PackageInfos: []types.PackageInfo(nil),
				Applications: []types.Application(nil),
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "yaml",
							Path: filepath.Join("testdata", "deployment_deny.yaml"),
							Content: []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-kubernetes
spec:
  replicas: 4
`),
						},
					},
				},
			},
		},
		{
			name: "happy path using anchors",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{filepath.Join("testdata", "deny.rego")},
			},
			inputFile: filepath.Join("testdata", "anchor.yaml"),
			want: &analyzer.AnalysisResult{
				OS:           (*types.OS)(nil),
				PackageInfos: []types.PackageInfo(nil),
				Applications: []types.Application(nil),
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "yaml",
							Path: filepath.Join("testdata", "anchor.yaml"),
							Content: []byte(`default: &default
  line: single line

john: &J
  john_name: john
fred: &F
  fred_name: fred

main:
  <<: *default
  name:
    <<: [*J, *F]
  comment: |
    multi
    line
`),
						},
					},
				},
			},
		},
		{
			name: "multiple yaml",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{filepath.Join("..", "testdata", "kubernetes.rego")},
			},
			inputFile: filepath.Join("testdata", "multiple.yaml"),
			want: &analyzer.AnalysisResult{
				OS:           (*types.OS)(nil),
				PackageInfos: []types.PackageInfo(nil),
				Applications: []types.Application(nil),
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "yaml",
							Path: filepath.Join("testdata", "multiple.yaml"),
							Content: []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-kubernetes
spec:
  replicas: 4

---

apiVersion: v1
kind: Service
metadata:
  name: hello-kubernetes
spec:
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
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

			a := yamlConfigAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
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
			s := yamlConfigAnalyzer{}

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yamlConfigAnalyzer_Type(t *testing.T) {
	s := yamlConfigAnalyzer{}

	want := analyzer.TypeYaml
	got := s.Type()
	assert.Equal(t, want, got)
}
