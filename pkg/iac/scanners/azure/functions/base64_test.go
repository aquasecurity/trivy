package functions

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Base64Call(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "simple base64 call",
			args: []interface{}{
				"hello, world",
			},
			expected: "aGVsbG8sIHdvcmxk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Base64(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}

func Test_Base64ToStringCall(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "simple base64ToString call",
			args: []interface{}{
				"aGVsbG8sIHdvcmxk",
			},
			expected: "hello, world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Base64ToString(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}

func Test_Base64ToJsonCall(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "simple base64ToJson call",
			args: []interface{}{
				"eyJoZWxsbyI6ICJ3b3JsZCJ9",
			},
			expected: `{"hello":"world"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Base64ToJson(tt.args...)

			actualContent, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, string(actualContent))
		})
	}
}
