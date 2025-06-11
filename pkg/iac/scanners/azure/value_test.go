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
