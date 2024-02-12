package functions

import "testing"

func Test_Mod(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name:     "Mod with 1 and 2",
			args:     []interface{}{1, 2},
			expected: 1,
		},
		{
			name:     "Mod with 2 and 3",
			args:     []interface{}{2, 3},
			expected: 2,
		},
		{
			name:     "Mod with 3 and -4",
			args:     []interface{}{3, -4},
			expected: 3,
		},
		{
			name:     "Mod with 7 and 3",
			args:     []interface{}{7, 3},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Mod(tt.args...)
			if got != tt.expected {
				t.Errorf("Mod() = %v, want %v", got, tt.expected)
			}
		})
	}
}
