package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "version with root.io suffix",
			input:    "1.2.3.root.io",
			expected: "1.2.3",
		},
		{
			name:     "version without suffix",
			input:    "1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "empty version",
			input:    "",
			expected: "",
		},
		{
			name:     "just suffix",
			input:    ".root.io",
			expected: "",
		},
		{
			name:     "complex version with suffix",
			input:    "2.0.0rc1.root.io",
			expected: "2.0.0rc1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAddVersionSuffix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "version without suffix",
			input:    "1.2.3",
			expected: "1.2.3.root.io",
		},
		{
			name:     "version already with suffix",
			input:    "1.2.3.root.io",
			expected: "1.2.3.root.io",
		},
		{
			name:     "empty version",
			input:    "",
			expected: ".root.io",
		},
		{
			name:     "complex version",
			input:    "2.0.0rc1",
			expected: "2.0.0rc1.root.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddVersionSuffix(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid version with suffix",
			input:    "1.2.3.root.io",
			expected: true,
		},
		{
			name:     "valid version without suffix",
			input:    "1.2.3",
			expected: true,
		},
		{
			name:     "invalid version",
			input:    "not-a-version",
			expected: false,
		},
		{
			name:     "empty version",
			input:    "",
			expected: false,
		},
		{
			name:     "valid pre-release with suffix",
			input:    "2.0.0rc1.root.io",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasRootIOSuffix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "with suffix",
			input:    "1.2.3.root.io",
			expected: true,
		},
		{
			name:     "without suffix",
			input:    "1.2.3",
			expected: false,
		},
		{
			name:     "just suffix",
			input:    ".root.io",
			expected: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasRootIOSuffix(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
