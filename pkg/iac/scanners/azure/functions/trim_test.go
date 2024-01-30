package functions

import "testing"

func Test_Trim(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "trim a string",
			args: []interface{}{
				" hello ",
			},
			expected: "hello",
		},
		{
			name: "trim a string with multiple spaces",
			args: []interface{}{
				"   hello   ",
			},
			expected: "hello",
		},
		{
			name: "trim a string with tabs",
			args: []interface{}{
				"	hello	",
			},
			expected: "hello",
		},
		{
			name: "trim a string with new lines",
			args: []interface{}{
				`

hello

`,
			},
			expected: "hello",
		},
		{
			name: "trim a string with tabs, spaces and new lines",
			args: []interface{}{
				`

hello

`,
			},
			expected: "hello",
		},
		{
			name: "trim a string with non string input",
			args: []interface{}{
				10,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Trim(tt.args...)
			if actual != tt.expected {
				t.Errorf("Trim(%v) = %v, expected %v", tt.args, actual, tt.expected)
			}
		})
	}
}
