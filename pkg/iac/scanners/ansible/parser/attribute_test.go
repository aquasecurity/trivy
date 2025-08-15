package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAttribute_GetNestedAttr(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		path     string
		expected any
	}{
		{
			name: "happy",
			src: `
tags:
  example: tag1`,
			path:     "tags.example",
			expected: "tag1",
		},
		{
			name:     "first level",
			src:      `name: mys3bucket`,
			path:     "name",
			expected: "mys3bucket",
		},
	}
	for _, tt := range tests {
		// TODO: build an attribute manually
		t.Run(tt.name, func(t *testing.T) {
			var attr Attribute
			err := yaml.Unmarshal([]byte(tt.src), &attr)
			require.NoError(t, err)

			got := attr.GetNestedAttr(tt.path).Value()
			assert.Equal(t, tt.expected, got)
		})
	}
}
