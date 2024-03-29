package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_If(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name:     "If with true",
			args:     []interface{}{true, "true", "false"},
			expected: "true",
		},
		{
			name:     "If with false",
			args:     []interface{}{false, "true", "false"},
			expected: "false",
		},
		{
			name: "If with true and slice returned",
			args: []interface{}{
				true,
				[]interface{}{"Hello", "World"},
				[]interface{}{"Goodbye", "World"},
			},
			expected: []interface{}{"Hello", "World"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := If(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}

}
