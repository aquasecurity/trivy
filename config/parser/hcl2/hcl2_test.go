package hcl2

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      interface{}
		wantErr   bool
	}{
		{
			name:      "terraform",
			inputFile: "testdata/main.tf",
			want: map[string]interface{}{
				"resource": map[string]interface{}{
					"aws_security_group_rule": map[string]interface{}{
						"my-rule": map[string]interface{}{
							"cidr_blocks": []interface{}{
								"0.0.0.0/0",
							},
							"type": "ingress",
						},
					},
					"azurerm_managed_disk": map[string]interface{}{
						"source": map[string]interface{}{
							"encryption_settings": map[string]interface{}{
								"enabled": "${var.enableEncryption}",
							},
						},
					},
				},
				"variable": map[string]interface{}{
					"enableEncryption": map[string]interface{}{
						"default": false,
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/broken.tf",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			var got interface{}
			err = Unmarshal(b, &got)
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
