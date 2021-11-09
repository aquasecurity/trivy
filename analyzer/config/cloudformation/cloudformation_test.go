package cloudformation

import (
	"context"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "CloudFormation yaml",
			filePath: "main.yaml",
			want:     true,
		},
		{
			name:     "Cloudformation JSON",
			filePath: "main.json",
			want:     true,
		},
		{
			name:     "non CloudFormation yaml",
			filePath: "k8s.yaml",
			want:     true,
		},
		{
			name:     "non CloudFormation json",
			filePath: "random.yaml",
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ConfigAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfigAnalyzer_Analyzed(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		filePath string
		want     int
	}{
		{
			name: "CloudFormation yaml",
			content: `---
Parameters:
  SomeParameter:
Resources:
  SomeResource:
    Type: Something
`,
			filePath: "main.yaml",
			want:     1,
		},
		{
			name: "Cloudformation JSON",
			content: `{
  "Parameters": {
    "SomeParameter": null
  },
  "Resources": {
    "SomeResource": {
      "Type": "Something"
    }
  }
}`,
			filePath: "main.json",
			want:     1,
		},
		{
			name: "non CloudFormation yaml",
			content: `---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  selector:
    matchLabels:
      app: nginx
  minReadySeconds: 5
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
`,
			filePath: "k8s.yaml",
			want:     0,
		},
		{
			name: "non CloudFormation json",
			content: `{
  "foo": [ 
       "baaaaa", 
       "bar", 
       "baa"
    ]
}
`,
			filePath: "random.yaml",
			want:     0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ConfigAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisTarget{
				FilePath: tt.filePath,
				Content:  []byte(tt.content),
			})
			require.NoError(t, err)
			assert.Len(t, got.Configs, tt.want)
		})
	}
}
