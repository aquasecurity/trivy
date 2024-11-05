package functions

import "testing"

func Test_CopyIndex(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected int
	}{
		{
			name:     "CopyIndex with 1",
			args:     []any{},
			expected: 1,
		},
		{
			name:     "CopyIndex with 2",
			args:     []any{},
			expected: 2,
		},
		{
			name:     "CopyIndex with 3",
			args:     []any{},
			expected: 3,
		},
		{
			name:     "CopyIndex with loopName",
			args:     []any{"loop1"},
			expected: 1,
		},
		{
			name: "CopyIndex with same lo" +
				"opName",
			args:     []any{"loop1"},
			expected: 2,
		},
		{
			name:     "CopyIndex with loopName",
			args:     []any{"loop2", 10},
			expected: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CopyIndex(tt.args...)
			if got != tt.expected {
				t.Errorf("CopyIndex() = %v, want %v", got, tt.expected)
			}
		})
	}
}
