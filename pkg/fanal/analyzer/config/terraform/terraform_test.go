package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "tf",
			filePath: "/path/to/main.tf",
			want:     true,
		},
		{
			name:     "tf.json",
			filePath: "/path/to/main.tf.json",
			want:     true,
		},
		{
			name:     "tfvars",
			filePath: "/path/to/some.tfvars",
			want:     true,
		},
		{
			name:     "json",
			filePath: "/path/to/some.json",
			want:     false,
		},
		{
			name:     "hcl",
			filePath: "/path/to/main.hcl",
			want:     false,
		},
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := terraformConfigAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
