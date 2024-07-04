package functions

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_UTCNow(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "utc now day",
			args: []any{
				"d",
			},
			expected: fmt.Sprintf("%d", time.Now().UTC().Day()),
		},
		{
			name: "utc now date",
			args: []any{
				"yyyy-M-d",
			},
			expected: fmt.Sprintf("%d-%d-%d", time.Now().UTC().Year(), time.Now().UTC().Month(), time.Now().UTC().Day()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := UTCNow(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
