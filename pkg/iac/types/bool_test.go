package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
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

func TestGetBoolFromValue(t *testing.T) {
	metadata := NewTestMetadata()

	tests := []struct {
		name     string
		ctyVal   cty.Value
		expected bool
		ok       bool
	}{
		// Bool
		{"bool true", cty.BoolVal(true), true, true},
		{"bool false", cty.BoolVal(false), false, true},

		// Strings (true)
		{"string 'true'", cty.StringVal("true"), true, true},
		{"string 'TRUE'", cty.StringVal("TRUE"), true, true},
		{"string 'yes'", cty.StringVal("yes"), true, true},
		{"string '1'", cty.StringVal("1"), true, true},

		// Strings (false)
		{"string 'false'", cty.StringVal("false"), false, true},
		{"string 'NO'", cty.StringVal("NO"), false, true},
		{"string '0'", cty.StringVal("0"), false, true},

		// Numbers
		{"number 1", cty.NumberIntVal(1), true, true},
		{"number 0", cty.NumberIntVal(0), false, true},
		{"number 42 (invalid)", cty.NumberIntVal(42), false, false},

		// Null / Unknown
		{"null", cty.NullVal(cty.Bool), false, false},
		{"unknown", cty.UnknownVal(cty.Bool), false, false},

		// Invalid string
		{"string 'maybe'", cty.StringVal("maybe"), false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := BoolFromCtyValue(tt.ctyVal, metadata)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.expected, got.Value())
			} else {
				assert.False(t, got.Value())
			}
		})
	}
}
