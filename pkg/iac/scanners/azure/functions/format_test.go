package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_FormatCall(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "simple format call",
			args: []interface{}{
				"{0}/{1}",
				"myPostgreSQLServer",
				"log_checkpoints",
			},
			expected: "myPostgreSQLServer/log_checkpoints",
		},
		{
			name: "complex format call",
			args: []interface{}{
				"{0} + {1} = {2}",
				1, 2, 3,
			},
			expected: "1 + 2 = 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Format(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
