package convert

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_StructConversion(t *testing.T) {
	tests := []struct {
		name     string
		inp      any
		expected any
	}{
		{
			name: "struct with nested struct",
			inp: struct {
				X string
				Y int
				Z struct {
					A float64
				}
			}{
				X: "test",
				Z: struct {
					A float64
				}{
					A: 123,
				},
			},
			expected: map[string]any{"z": make(map[string]any)},
		},
		{
			name: "struct with metadata",
			inp: struct {
				X        string
				Metadata types.Metadata
			}{
				X:        "test",
				Metadata: types.NewTestMetadata(),
			},
			expected: map[string]any{
				"__defsec_metadata": func() any {
					meta := types.NewTestMetadata().GetMetadata()
					return meta.ToRego()
				}(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converted := StructToRego(reflect.ValueOf(tt.inp))
			assert.Equal(t, tt.expected, converted)
		})
	}
}
