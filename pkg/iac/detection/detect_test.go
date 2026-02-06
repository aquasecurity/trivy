package detection

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
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
				FileTypeAnsible,
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
				FileTypeAnsible,
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
			name: "tofu, no reader",
			path: "main.tofu",
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "tofu, with reader",
			path: "main.tofu",
			r:    strings.NewReader("some file content"),
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "tofu json, no reader",
			path: "main.tofu.json",
			expected: []FileType{
				FileTypeTerraform,
				FileTypeJSON,
				FileTypeAnsible,
			},
		},
		{
			name: "tofu json, with reader",
			path: "main.tofu.json",
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
				FileTypeAnsible,
			},
		},
		{
			name: "cloudformation, no reader",
			path: "main.yaml",
			expected: []FileType{
				FileTypeYAML,
				FileTypeHelm,
				FileTypeAnsible,
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
				FileTypeAnsible,
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
				FileTypeAnsible,
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
				FileTypeAnsible,
			},
		},
		{
			name: "Dockerfile, no reader",
			path: "Dockerfile",
			r:    nil,
			expected: []FileType{
				FileTypeDockerfile,
				FileTypeAnsible,
			},
		},
		{
			name: "Containerfile, no reader",
			path: "Containerfile",
			r:    nil,
			expected: []FileType{
				FileTypeDockerfile,
				FileTypeAnsible,
			},
		},
		{
			name: "Dockerfile, reader",
			path: "Dockerfile",
			r:    strings.NewReader("FROM ubuntu\n"),
			expected: []FileType{
				FileTypeDockerfile,
				FileTypeAnsible,
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
				FileTypeHelm,
				FileTypeAnsible,
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
				FileTypeHelm,
				FileTypeAnsible,
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
				FileTypeAnsible,
			},
		},
		{
			name: "YAML, no reader",
			path: "file.yaml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
				FileTypeHelm,
				FileTypeAnsible,
			},
		},
		{
			name: "YML, no reader",
			path: "file.yml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
				FileTypeHelm,
				FileTypeAnsible,
			},
		},
		{
			name: "YML uppercase",
			path: "file.YML",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
				FileTypeHelm,
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
				FileTypeAnsible,
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
				FileTypeHelm,
				FileTypeAnsible,
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
				FileTypeHelm,
				FileTypeAnsible,
			},
		},
		{
			name: "kubernetes, multi-doc with non-map doc first",
			path: "k8s.yaml",
			r: strings.NewReader(`---
- this is a list, not a map
---
apiVersion: v1
kind: Service
metadata:
  name: valid-service
`),
			expected: []FileType{
				FileTypeKubernetes,
				FileTypeYAML,
				FileTypeHelm,
				FileTypeAnsible,
			},
		},
		{
			name: "Azure ARM template with resources",
			path: "test.json",
			r: strings.NewReader(`
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2021-09-01",
      "name": "{provide-unique-name}",
      "location": "eastus",
      "sku": {
        "name": "Standard_LRS"
      },
      "kind": "StorageV2",
      "properties": {
        "supportsHttpsTrafficOnly": true
      }
    }
  ]
}
`),
			expected: []FileType{
				FileTypeJSON,
				FileTypeAzureARM,
				FileTypeAnsible,
			},
		},
		{
			name: "Azure ARM resources defined as an object",
			path: "test.json",
			r: strings.NewReader(`{
  "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
  "languageVersion": "2.0",
  "contentVersion": "1.0.0.0",
  "resources": {
    "myacc": {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2025-06-01",
      "name": "my-acc-test",
      "location": "location",
			"kind": "Storage"
    }
  }
}`),
			expected: []FileType{
				FileTypeJSON,
				FileTypeCloudFormation,
				FileTypeAzureARM,
				FileTypeAnsible,
			},
		},
		{
			name: "Azure ARM template with parameters",
			path: "test.json",
			r: strings.NewReader(`
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "storageName": {
      "type": "string",
      "minLength": 3,
      "maxLength": 24
    }
  }
}
`),
			expected: []FileType{
				FileTypeJSON,
				FileTypeAzureARM,
				FileTypeAnsible,
			},
		},
		{
			name: "empty Azure ARM template",
			path: "test.json",
			r: strings.NewReader(`
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": []
}
`),
			expected: []FileType{
				FileTypeJSON,
				FileTypeAnsible,
			},
		},
		{
			name: "CreateUiDefinition",
			path: "CreateUiDefinition.json",
			r: strings.NewReader(`{
  "$schema": "https://schema.management.azure.com/schemas/0.1.2-preview/CreateUIDefinition.MultiVm.json#",
  "handler": "Microsoft.Azure.CreateUIDef",
  "version": "0.1.2-preview",
  "parameters": {
    "config": {
      "isWizard": false,
      "basics": {}
    },
    "basics": [],
    "steps": [],
    "outputs": {},
    "resourceTypes": []
  }
}`),
			expected: []FileType{
				FileTypeJSON,
				FileTypeAnsible,
			},
		},
		{
			name: "without extension",
			path: "something",
			expected: []FileType{
				FileTypeAnsible,
			},
		},
		{
			name: "Ansible inventory INI file",
			path: "something.ini",
			expected: []FileType{
				FileTypeAnsible,
			},
		},
		{
			name: "Ansible config file",
			path: "ansible.cfg",
			expected: []FileType{
				FileTypeAnsible,
			},
		},
		{
			name:     " not Ansible config file",
			path:     "something.cfg",
			expected: []FileType{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("GetTypes", func(t *testing.T) {
				actualDetections := GetTypes(test.path, test.r)
				assert.Len(t, actualDetections, len(test.expected))
				for _, expected := range test.expected {
					resetReader(test.r)
					found := slices.Contains(actualDetections, expected)
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
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		_ = IsType(fmt.Sprintf("./testdata/%s", "small.file"), bytes.NewReader(data), FileTypeAzureARM)
	}
}

func BenchmarkIsType_BigFile(b *testing.B) {
	data, err := os.ReadFile(fmt.Sprintf("./testdata/%s", "big.file"))
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		_ = IsType(fmt.Sprintf("./testdata/%s", "big.file"), bytes.NewReader(data), FileTypeAzureARM)
	}
}

func Test_IsFileMatchesSchemas(t *testing.T) {

	schema := `{
  "$id": "https://example.com/test.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "service": { "type": "string" }
  },
  "required": ["service"]
}`

	schema2 := `{
	"$id": "https://example.com/test.schema.json",
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
	  "provider": { "type": "string" }
	},
	"required": ["provider"]
  }`

	type args struct {
		schemas     []string
		fileType    FileType
		fileName    string
		fileContent string
	}
	tests := []struct {
		name    string
		args    args
		matches bool
	}{
		{
			name: "json file matches",
			args: args{
				schemas:  []string{schema},
				fileType: FileTypeJSON,
				fileName: "test.json",
				fileContent: `{
  "service": "test"
}`,
			},
			matches: true,
		},
		{
			name: "json file dost not matches",
			args: args{
				schemas:  []string{schema},
				fileType: FileTypeJSON,
				fileName: "test.json",
				fileContent: `{
  "somefield": "test",
}`,
			},
			matches: false,
		},
		{
			name: "json file matches, but file type is yaml",
			args: args{
				schemas:  []string{schema},
				fileType: FileTypeYAML,
				fileName: "test.json",
				fileContent: `{
  "service": "test"
}`,
			},
			matches: false,
		},
		{
			name: "broken json file",
			args: args{
				schemas:  []string{schema},
				fileType: FileTypeJSON,
				fileName: "test.json",
				fileContent: `{
  "service": "test",,
}`,
			},
			matches: false,
		},
		{
			name: "yaml file matches",
			args: args{
				schemas:     []string{schema},
				fileType:    FileTypeYAML,
				fileName:    "test.yml",
				fileContent: `service: test`,
			},
			matches: true,
		},
		{
			name: "yaml file does not matches",
			args: args{
				schemas:     []string{schema},
				fileType:    FileTypeYAML,
				fileName:    "test.yaml",
				fileContent: `somefield: test`,
			},
			matches: false,
		},
		{
			name: "broken yaml file",
			args: args{
				schemas:  []string{schema},
				fileType: FileTypeYAML,
				fileName: "test.yaml",
				fileContent: `text foobar
number: 2`,
			},
			matches: false,
		},
		{
			name: "multiple schemas",
			args: args{
				schemas:     []string{schema, schema2},
				fileType:    FileTypeYAML,
				fileName:    "test.yaml",
				fileContent: `provider: test`,
			},
			matches: true,
		},
	}
	for _, tt := range tests {
		schemas := make(map[string]*gojsonschema.Schema)
		for i, content := range tt.args.schemas {
			l := gojsonschema.NewStringLoader(content)
			s, err := gojsonschema.NewSchema(l)
			require.NoError(t, err)
			schemas[fmt.Sprintf("schema-%d.json", i)] = s
		}
		rs := strings.NewReader(tt.args.fileContent)
		got := IsFileMatchesSchemas(schemas, tt.args.fileType, tt.args.fileName, rs)
		assert.Equal(t, tt.matches, got)
	}
}
