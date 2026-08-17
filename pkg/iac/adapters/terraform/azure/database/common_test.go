package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_minimumTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		val      string
		expected string
	}{
		{
			name:     "single version",
			val:      "TLSv1.2",
			expected: "TLS1_2",
		},
		{
			name:     "TLSv1 without a minor version",
			val:      "TLSv1",
			expected: "TLS1_0",
		},
		{
			name:     "mixed case",
			val:      "tlsV1.3",
			expected: "TLS1_3",
		},
		{
			name:     "list with the lowest version last",
			val:      "TLSv1.3,TLSv1.2",
			expected: "TLS1_2",
		},
		{
			name:     "list with spaces",
			val:      "TLSv1.1, TLSv1.2 , TLSv1.3",
			expected: "TLS1_1",
		},
		{
			name:     "trailing comma",
			val:      "TLSv1.2,",
			expected: "TLS1_2",
		},
		{
			name:     "empty value",
			val:      "",
			expected: "",
		},
		{
			name:     "unrecognized version is skipped",
			val:      "TLSv1.2,TLSv1.4",
			expected: "TLS1_2",
		},
		{
			name:     "value with no recognized version is returned as is",
			val:      "TLSv1.4",
			expected: "TLSv1.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, minimumTLSVersion(tt.val))
		})
	}
}
