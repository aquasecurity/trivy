package detection

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Detection(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		r        io.ReadSeeker
		expected []FileType
	}{
		{
			name:     "text file, no reader",
			path:     "something.txt",
			expected: nil,
		},
		{
			name:     "text file, with reader",
			path:     "something.txt",
			r:        strings.NewReader("some file content"),
			expected: nil,
		},
		{
			name: "terraform, no reader",
			path: "main.tf",
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "terraform, with reader",
			path: "main.tf",
			r:    strings.NewReader("some file content"),
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "terraform json, no reader",
			path: "main.tf.json",
			expected: []FileType{
				FileTypeTerraform,
				FileTypeJSON,
			},
		},
		{
			name: "terraform json, with reader",
			path: "main.tf.json",
			r: strings.NewReader(`
{
  "variable": {
    "example": {
      "default": "hello"
    }
  }
}
`),
			expected: []FileType{
				FileTypeTerraform,
				FileTypeJSON,
			},
		},
		{
			name: "terraform vars, no reader",
			path: "main.tfvars",
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "terraform vars, with reader",
			path: "main.tfvars",
			r:    strings.NewReader("some_var = \"some value\""),
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "cloudformation, no reader",
			path: "main.yaml",
			expected: []FileType{
				FileTypeYAML,
				FileTypeHelm,
			},
		},
		{
			name: "terraform plan, with reader",
			path: "plan.json",
			r: strings.NewReader(`{
				"format_version": "0.2",
				"terraform_version": "1.0.3",
				"variables": {
					"bucket_name": {
						"value": "tfsec-plan-testing"
					}
				},
				"planned_values": {},
				"resource_changes": [],
				"prior_state": {},
				"configuration": {}
			}`),
			expected: []FileType{
				FileTypeTerraformPlanJSON,
				FileTypeJSON,
			},
		},
		{
			name: "cloudformation, with reader",
			path: "main.yaml",
			r: strings.NewReader(`---
AWSTemplateFormatVersion: 2010-09-09

Description: CodePipeline for continuous integration and continuous deployment

Parameters:
  RepositoryName:
    Type: String
    Description: Name of the CodeCommit repository
  BuildDockerImage:
    Type: String
    Default: aws/codebuild/ubuntu-base:14.04
    Description: Docker image to use for the build phase
  DeployDockerImage:
    Type: String
    Default: aws/codebuild/ubuntu-base:14.04
    Description: Docker image to use for the deployment phase

Resources:
  PipelineS3Bucket:
    Type: AWS::S3::Bucket
`),
			expected: []FileType{
				FileTypeCloudFormation,
				FileTypeYAML,
				FileTypeHelm,
			},
		},
		{
			name: "JSON with Resources, not cloudformation",
			path: "whatever.json",
			r: strings.NewReader(`{
  "Resources": ["something"]
}`),
			expected: []FileType{
				FileTypeJSON,
			},
		},
		{
			name: "Dockerfile, no reader",
			path: "Dockerfile",
			r:    nil,
			expected: []FileType{
				FileTypeDockerfile,
			},
		},
		{
			name: "Containerfile, no reader",
			path: "Containerfile",
			r:    nil,
			expected: []FileType{
				FileTypeDockerfile,
			},
		},
		{
			name: "Dockerfile, reader",
			path: "Dockerfile",
			r:    strings.NewReader("FROM ubuntu\n"),
			expected: []FileType{
				FileTypeDockerfile,
			},
		},
		{
			name: "Dockerfile extension",
			path: "lol.Dockerfile",
			r:    nil,
			expected: []FileType{
				FileTypeDockerfile,
			},
		},
		{
			name: "kubernetes, no reader",
			path: "k8s.yml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "kubernetes, reader",
			path: "k8s.yml",
			r: strings.NewReader(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80`),
			expected: []FileType{
				FileTypeKubernetes,
				FileTypeYAML,
			},
		},
		{
			name: "kubernetes, reader, JSON",
			path: "k8s.json",
			r: strings.NewReader(`{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
    "name": "nginx-deployment",
    "labels": {
      "app": "nginx"
    }
  },
  "spec": {
    "replicas": 3,
    "selector": {
      "matchLabels": {
        "app": "nginx"
      }
    },
    "template": {
      "metadata": {
        "labels": {
          "app": "nginx"
        }
      },
      "spec": {
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:1.14.2",
            "ports": [
              {
                "containerPort": 80
              }
            ]
          }
        ]
      }
    }
  }
}`),
			expected: []FileType{
				FileTypeKubernetes,
				FileTypeJSON,
			},
		},
		{
			name: "YAML, no reader",
			path: "file.yaml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
				FileTypeHelm,
			},
		},
		{
			name: "YML, no reader",
			path: "file.yml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "YML uppercase",
			path: "file.YML",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "TOML, no reader",
			path: "file.toml",
			r:    nil,
			expected: []FileType{
				FileTypeTOML,
			},
		},
		{
			name: "JSON, no reader",
			path: "file.json",
			r:    nil,
			expected: []FileType{
				FileTypeJSON,
			},
		},
		{
			name: "kubernetes, configmap",
			path: "k8s.yml",
			r: strings.NewReader(`apiVersion: v1
kind: ConfigMap
metadata:
  name: test
  namespace: default
data:
  AWS_ACCESS_KEY_ID: "XXX"
  AWS_SECRET_ACCESS_KEY: "XXX"`),
			expected: []FileType{
				FileTypeKubernetes,
				FileTypeYAML,
			},
		},
		{
			name: "kubernetes, clusterRole",
			path: "k8s.yml",
			r: strings.NewReader(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
  name: view
rules:
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  - ingresses/status
  - networkpolicies
  verbs:
  - get
  - list
  - watch`),
			expected: []FileType{
				FileTypeKubernetes,
				FileTypeYAML,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("GetTypes", func(t *testing.T) {
				actualDetections := GetTypes(test.path, test.r)
				assert.Equal(t, len(test.expected), len(actualDetections))
				for _, expected := range test.expected {
					resetReader(test.r)
					var found bool
					for _, actual := range actualDetections {
						if actual == expected {
							found = true
							break
						}
					}
					assert.True(t, found, "%s should be detected", expected)
				}
			})
			for _, expected := range test.expected {
				resetReader(test.r)
				t.Run(fmt.Sprintf("IsType_%s", expected), func(t *testing.T) {
					assert.True(t, IsType(test.path, test.r, expected))
				})
			}
			t.Run("IsType_invalid", func(t *testing.T) {
				resetReader(test.r)
				assert.False(t, IsType(test.path, test.r, "invalid"))
			})
		})
	}
}

func BenchmarkIsType_SmallFile(b *testing.B) {
	data, err := os.ReadFile(fmt.Sprintf("./testdata/%s", "small.file"))
	assert.Nil(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsType(fmt.Sprintf("./testdata/%s", "small.file"), bytes.NewReader(data), FileTypeAzureARM)
	}
}

func BenchmarkIsType_BigFile(b *testing.B) {
	data, err := os.ReadFile(fmt.Sprintf("./testdata/%s", "big.file"))
	assert.Nil(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsType(fmt.Sprintf("./testdata/%s", "big.file"), bytes.NewReader(data), FileTypeAzureARM)
	}
}
