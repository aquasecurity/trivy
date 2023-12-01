package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zclconf/go-cty/cty"
)

func TestValidateForEachArg(t *testing.T) {
	tests := []struct {
		name          string
		arg           cty.Value
		expectedError string
	}{
		{
			name: "empty set",
			arg:  cty.SetValEmpty(cty.String),
		},
		{
			name: "set of strings",
			arg:  cty.SetVal([]cty.Value{cty.StringVal("val1"), cty.StringVal("val2")}),
		},
		{
			name:          "set of non-strings",
			arg:           cty.SetVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2)}),
			expectedError: "is not set of strings",
		},
		{
			name:          "set with null",
			arg:           cty.SetVal([]cty.Value{cty.StringVal("val1"), cty.NullVal(cty.String)}),
			expectedError: "arg is set of strings, but contains null",
		},
		{
			name:          "set with unknown",
			arg:           cty.SetVal([]cty.Value{cty.StringVal("val1"), cty.UnknownVal(cty.String)}),
			expectedError: "arg is set of strings, but contains unknown",
		},
		{
			name:          "set with unknown",
			arg:           cty.SetVal([]cty.Value{cty.StringVal("val1"), cty.UnknownVal(cty.String)}),
			expectedError: "arg is set of strings, but contains unknown",
		},
		{
			name: "non empty map",
			arg: cty.MapVal(map[string]cty.Value{
				"val1": cty.StringVal("..."),
				"val2": cty.StringVal("..."),
			}),
		},
		{
			name: "map with unknown",
			arg: cty.MapVal(map[string]cty.Value{
				"val1": cty.UnknownVal(cty.String),
				"val2": cty.StringVal("..."),
			}),
		},
		{
			name: "empty obj",
			arg:  cty.EmptyObjectVal,
		},
		{
			name: "obj with strings",
			arg: cty.ObjectVal(map[string]cty.Value{
				"val1": cty.StringVal("..."),
				"val2": cty.StringVal("..."),
			}),
		},
		{
			name:          "null",
			arg:           cty.NullVal(cty.Set(cty.String)),
			expectedError: "arg is null",
		},
		{
			name: "unknown",
			arg:  cty.UnknownVal(cty.Set(cty.String)),
		},
		{
			name: "dynamic",
			arg:  cty.DynamicVal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateForEachArg(tt.arg)
			if tt.expectedError != "" && err != nil {
				assert.ErrorContains(t, err, tt.expectedError)
				return
			}
			assert.NoError(t, err)
		})
	}
}
