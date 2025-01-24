package parser_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
)

func TestManifestToRego(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected any
	}{
		{
			name: "timestamp tag",
			src:  `field: !!timestamp 2024-04-01`,
			expected: map[string]any{
				"__defsec_metadata": map[string]any{
					"filepath":  "",
					"offset":    0,
					"startline": 1,
					"endline":   1,
				},
				"field": "2024-04-01T00:00:00Z",
			},
		},
		{
			name: "binary tag",
			src:  `field: !!binary dGVzdA==`,
			expected: map[string]any{
				"__defsec_metadata": map[string]any{
					"filepath":  "",
					"offset":    0,
					"startline": 1,
					"endline":   1,
				},
				"field": []uint8{0x74, 0x65, 0x73, 0x74},
			},
		},
		{
			name: "float tag",
			src:  `field: 1.1`,
			expected: map[string]any{
				"__defsec_metadata": map[string]any{
					"filepath":  "",
					"offset":    0,
					"startline": 1,
					"endline":   1,
				},
				"field": 1.1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var manifest parser.Manifest
			err := yaml.Unmarshal([]byte(tt.src), &manifest)
			require.NoError(t, err)
			data := manifest.ToRego()
			assert.Equal(t, tt.expected, data)
		})
	}
}
