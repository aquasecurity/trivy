package azure

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_ValueAsInt(t *testing.T) {
	val := NewValue(int64(10), types.NewTestMetadata())
	assert.Equal(t, 10, val.AsInt())
}

func Test_ValueAsBool(t *testing.T) {
	tests := []struct {
		name         string
		val          any
		defaultValue bool
		expected     bool
	}{
		{
			name:         "bool true",
			val:          true,
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "bool false",
			val:          false,
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "string true",
			val:          "true",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "string Enabled",
			val:          "Enabled",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "string false",
			val:          "false",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "string Disabled",
			val:          "Disabled",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "string 0",
			val:          "0",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "string no",
			val:          "no",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "string off",
			val:          "off",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "unrecognized string uses default true",
			val:          "unknown",
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "nil uses default true",
			val:          nil,
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "nil uses default false",
			val:          nil,
			defaultValue: false,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := NewValue(tt.val, types.NewTestMetadata())
			got := val.AsBoolValue(tt.defaultValue, types.NewTestMetadata()).Value()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func Test_ValueAsTime(t *testing.T) {
	tests := []struct {
		name     string
		val      any
		expected time.Time
	}{
		{
			name:     "string",
			val:      "2023-12-15T14:45:00Z",
			expected: time.Date(2023, 12, 15, 14, 45, 0, 0, time.UTC),
		},
		{
			name:     "int",
			val:      int64(200),
			expected: time.Unix(200, 0),
		},
		{
			name:     "float",
			val:      float64(100),
			expected: time.Unix(100, 0),
		},
		{
			name:     "invalid type",
			val:      nil,
			expected: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := NewValue(tt.val, types.NewTestMetadata())
			got := val.AsTimeValue(types.NewTestMetadata()).Value()
			assert.Equal(t, tt.expected, got)
		})
	}
}
