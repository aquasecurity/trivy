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
			name: "use timestamp tag",
			src:  `global: !!timestamp 2024-04-01`,
			expected: map[string]any{
				"__defsec_metadata": map[string]any{
					"filepath":  "",
					"offset":    0,
					"startline": 1,
					"endline":   1,
				},
				"global": "2024-04-01T00:00:00Z",
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
