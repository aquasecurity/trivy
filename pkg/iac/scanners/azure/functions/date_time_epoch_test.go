package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DateTimeFromEpoch(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "datetime from epoch",
			args: []interface{}{
				1683040573,
			},
			expected: "2023-05-02T15:16:13Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := DateTimeFromEpoch(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_DateTimeToEpoch(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "datetime to epoch",
			args: []interface{}{
				"2023-05-02T15:16:13Z",
			},
			expected: 1683040573,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := DateTimeToEpoch(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
