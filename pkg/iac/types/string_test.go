package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StringValueStartsWith(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		prefix   string
		expected bool
	}{
		{
			desc:     "return true when starts with",
			input:    "something",
			prefix:   "some",
			expected: true,
		},
		{
			desc:     "return false when does not start with",
			input:    "something",
			prefix:   "nothing",
			expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.expected, String(tc.input, fakeMetadata).StartsWith(tc.prefix))
		})
	}
}

func Test_StringJSON(t *testing.T) {
	val := String("hello world", NewMetadata(NewRange("main.tf", 123, 123, "", nil), ""))
	data, err := json.Marshal(val)
	require.NoError(t, err)

	var restored StringValue
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, val, restored)
}
