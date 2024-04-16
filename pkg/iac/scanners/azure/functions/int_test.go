package functions

import "testing"

func Test_Int(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name:     "Int with 1",
			args:     []interface{}{1},
			expected: 1,
		},
		{
			name:     "Int with 2",
			args:     []interface{}{"2"},
			expected: 2,
		},
		{
			name:     "Int with 2.3",
			args:     []interface{}{"2.3"},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Int(tt.args...)
			if got != tt.expected {
				t.Errorf("Int() = %v, want %v", got, tt.expected)
			}
		})
	}
}
