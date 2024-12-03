package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fakeMetadata = NewMetadata(NewRange("main.tf", 123, 123, "", nil), "")

func Test_BoolValueIsTrue(t *testing.T) {
	testCases := []struct {
		desc     string
		value    bool
		expected bool
	}{
		{
			desc:     "returns true when isTrue",
			value:    true,
			expected: true,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

			val := Bool(tC.value, fakeMetadata)

			assert.Equal(t, tC.expected, val.IsTrue())
		})
	}
}

func Test_BoolJSON(t *testing.T) {
	val := Bool(true, NewMetadata(NewRange("main.tf", 123, 123, "", nil), ""))
	data, err := json.Marshal(val)
	require.NoError(t, err)

	var restored BoolValue
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, val, restored)
}
