package yaml_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/config/parser/yaml"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      interface{}
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/deployment.yaml",
			want: map[string]interface{}{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)
			p := yaml.Parser{}
			got, err := p.Parse(b)
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

func TestParser_SeparateSubDocuments(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want [][]byte
	}{
		{
			name: "happy path",
			data: []byte(`kind: Pod
---
kind: Service`),
			want: [][]byte{
				[]byte(`kind: Pod`),
				[]byte(`kind: Service`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &yaml.Parser{}
			got := p.SeparateSubDocuments(tt.data)
			assert.Equal(t, tt.want, got)
		})
	}
}
