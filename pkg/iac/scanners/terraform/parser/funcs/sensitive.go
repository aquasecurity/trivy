// Copied from github.com/hashicorp/terraform/internal/lang/funcs
package funcs

import (
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// SensitiveFunc returns a value identical to its argument except that
// Terraform will consider it to be sensitive.
var SensitiveFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name:             "value",
			Type:             cty.DynamicPseudoType,
			AllowUnknown:     true,
			AllowNull:        true,
			AllowMarked:      true,
			AllowDynamicType: true,
		},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		// This function only affects the value's marks, so the result
		// type is always the same as the argument type.
		return args[0].Type(), nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
		val, _ := args[0].Unmark()
		return val.Mark(MarkedSensitive), nil
	},
})

// NonsensitiveFunc takes a sensitive value and returns the same value without
// the sensitive marking, effectively exposing the value.
var NonsensitiveFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name:             "value",
			Type:             cty.DynamicPseudoType,
			AllowUnknown:     true,
			AllowNull:        true,
			AllowMarked:      true,
			AllowDynamicType: true,
		},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		// This function only affects the value's marks, so the result
		// type is always the same as the argument type.
		return args[0].Type(), nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
		v, marks := args[0].Unmark()
		delete(marks, MarkedSensitive) // remove the sensitive marking
		return v.WithMarks(marks), nil
	},
})

var IssensitiveFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name:             "value",
		Type:             cty.DynamicPseudoType,
		AllowUnknown:     true,
		AllowNull:        true,
		AllowMarked:      true,
		AllowDynamicType: true,
	}},
	Type: func(args []cty.Value) (cty.Type, error) {
		return cty.Bool, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		s := args[0].HasMark(MarkedSensitive)
		return cty.BoolVal(s), nil
	},
})
