package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DateTimeAdd(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{

		{
			name: "datetime add 1 years",
			args: []interface{}{
				"2010-01-01T00:00:00Z",
				"P1Y",
			},
			expected: "2011-01-01T00:00:00Z",
		},
		{
			name: "datetime add 3 months",
			args: []interface{}{
				"2010-01-01T00:00:00Z",
				"P3M",
			},
			expected: "2010-04-01T00:00:00Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := DateTimeAdd(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_ISO8601DurationParse(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		expected Iso8601Duration
	}{

		{
			name:     "parse 1 year",
			args:     "P1Y",
			expected: Iso8601Duration{Y: 1},
		},
		{
			name:     "parse 3 months",
			args:     "P3M",
			expected: Iso8601Duration{M: 3},
		},
		{
			name:     "parse 12 hours",
			args:     "PT12H",
			expected: Iso8601Duration{TH: 12},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := parseISO8601(tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
