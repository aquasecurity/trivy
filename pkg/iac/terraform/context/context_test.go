package context

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

func Test_ContextVariables(t *testing.T) {
	underlying := &hcl.EvalContext{}
	ctx := NewContext(underlying, nil)

	val, err := gocty.ToCtyValue("hello", cty.String)
	if err != nil {
		t.Fatal(err)
	}

	ctx.Set(val, "my", "value")
	value := underlying.Variables["my"].AsValueMap()["value"]
	assert.Equal(t, "hello", value.AsString())

}

func Test_ContextVariablesPreservation(t *testing.T) {

	underlying := &hcl.EvalContext{}
	underlying.Variables = make(map[string]cty.Value)
	underlying.Variables["x"], _ = gocty.ToCtyValue("does it work?", cty.String)
	str, _ := gocty.ToCtyValue("something", cty.String)
	underlying.Variables["my"] = cty.ObjectVal(map[string]cty.Value{
		"other": str,
		"obj": cty.ObjectVal(map[string]cty.Value{
			"another": str,
		}),
	})
	ctx := NewContext(underlying, nil)

	val, err := gocty.ToCtyValue("hello", cty.String)
	if err != nil {
		t.Fatal(err)
	}

	ctx.Set(val, "my", "value")
	assert.Equal(t, "hello", underlying.Variables["my"].AsValueMap()["value"].AsString())
	assert.Equal(t, "something", underlying.Variables["my"].AsValueMap()["other"].AsString())
	assert.Equal(t, "something", underlying.Variables["my"].AsValueMap()["obj"].AsValueMap()["another"].AsString())
	assert.Equal(t, "does it work?", underlying.Variables["x"].AsString())

}

func Test_SetWithMerge(t *testing.T) {
	hctx := hcl.EvalContext{
		Variables: map[string]cty.Value{
			"my": cty.ObjectVal(map[string]cty.Value{
				"someValue": cty.ObjectVal(map[string]cty.Value{
					"foo": cty.StringVal("test"),
					"bar": cty.ObjectVal(map[string]cty.Value{
						"foo": cty.StringVal("test"),
					}),
				}),
			}),
		},
	}

	ctx := NewContext(&hctx, nil)

	val := cty.ObjectVal(map[string]cty.Value{
		"foo2": cty.StringVal("test2"),
		"bar": cty.ObjectVal(map[string]cty.Value{
			"foo2": cty.StringVal("test2"),
		}),
	})

	ctx.Set(val, "my", "someValue")
	got := ctx.Get("my", "someValue")
	expected := cty.ObjectVal(map[string]cty.Value{
		"foo":  cty.StringVal("test"),
		"foo2": cty.StringVal("test2"),
		"bar": cty.ObjectVal(map[string]cty.Value{
			"foo":  cty.StringVal("test"),
			"foo2": cty.StringVal("test2"),
		}),
	})

	assert.Equal(t, expected, got)
}

func Test_ContextVariablesPreservationByDot(t *testing.T) {

	underlying := &hcl.EvalContext{}
	underlying.Variables = make(map[string]cty.Value)
	underlying.Variables["x"], _ = gocty.ToCtyValue("does it work?", cty.String)
	str, _ := gocty.ToCtyValue("something", cty.String)
	underlying.Variables["my"] = cty.ObjectVal(map[string]cty.Value{
		"other": str,
		"obj": cty.ObjectVal(map[string]cty.Value{
			"another": str,
		}),
	})
	ctx := NewContext(underlying, nil)

	val, err := gocty.ToCtyValue("hello", cty.String)
	if err != nil {
		t.Fatal(err)
	}

	ctx.SetByDot(val, "my.something.value")
	assert.Equal(t, "hello", underlying.Variables["my"].AsValueMap()["something"].AsValueMap()["value"].AsString())
	assert.Equal(t, "something", underlying.Variables["my"].AsValueMap()["other"].AsString())
	assert.Equal(t, "something", underlying.Variables["my"].AsValueMap()["obj"].AsValueMap()["another"].AsString())
	assert.Equal(t, "does it work?", underlying.Variables["x"].AsString())
}

func Test_ContextSetThenImmediateGet(t *testing.T) {

	underlying := &hcl.EvalContext{}

	ctx := NewContext(underlying, nil)

	ctx.Set(cty.ObjectVal(map[string]cty.Value{
		"mod_result": cty.StringVal("ok"),
	}), "module", "modulename")

	val := ctx.Get("module", "modulename", "mod_result")
	assert.Equal(t, "ok", val.AsString())
}

func Test_ContextSetThenImmediateGetWithChild(t *testing.T) {

	underlying := &hcl.EvalContext{}

	ctx := NewContext(underlying, nil)

	childCtx := ctx.NewChild()

	childCtx.Root().Set(cty.ObjectVal(map[string]cty.Value{
		"mod_result": cty.StringVal("ok"),
	}), "module", "modulename")

	val := ctx.Get("module", "modulename", "mod_result")
	assert.Equal(t, "ok", val.AsString())
}

func Test_MergeObjects(t *testing.T) {

	tests := []struct {
		name     string
		oldVal   cty.Value
		newVal   cty.Value
		expected cty.Value
	}{
		{
			name: "happy",
			oldVal: cty.ObjectVal(map[string]cty.Value{
				"this": cty.ObjectVal(map[string]cty.Value{
					"id":  cty.StringVal("some_id"),
					"arn": cty.StringVal("some_arn"),
				}),
			}),
			newVal: cty.ObjectVal(map[string]cty.Value{
				"this": cty.ObjectVal(map[string]cty.Value{
					"arn":    cty.StringVal("some_new_arn"),
					"bucket": cty.StringVal("test"),
				}),
			}),
			expected: cty.ObjectVal(map[string]cty.Value{
				"this": cty.ObjectVal(map[string]cty.Value{
					"id":     cty.StringVal("some_id"),
					"arn":    cty.StringVal("some_new_arn"),
					"bucket": cty.StringVal("test"),
				}),
			}),
		},
		{
			name:   "old value is empty",
			oldVal: cty.EmptyObjectVal,
			newVal: cty.ObjectVal(map[string]cty.Value{
				"this": cty.ObjectVal(map[string]cty.Value{
					"bucket": cty.StringVal("test"),
				}),
			}),
			expected: cty.ObjectVal(map[string]cty.Value{
				"this": cty.ObjectVal(map[string]cty.Value{
					"bucket": cty.StringVal("test"),
				}),
			}),
		},
		{
			name: "new value is empty",
			oldVal: cty.ObjectVal(map[string]cty.Value{
				"this": cty.ObjectVal(map[string]cty.Value{
					"bucket": cty.StringVal("test"),
				}),
			}),
			newVal: cty.EmptyObjectVal,
			expected: cty.ObjectVal(map[string]cty.Value{
				"this": cty.ObjectVal(map[string]cty.Value{
					"bucket": cty.StringVal("test"),
				}),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mergeObjects(tt.oldVal, tt.newVal))
		})
	}

}

func Test_IsNotEmptyObject(t *testing.T) {
	tests := []struct {
		name     string
		val      cty.Value
		expected bool
	}{
		{
			name: "happy",
			val: cty.ObjectVal(map[string]cty.Value{
				"field": cty.NilVal,
			}),
			expected: true,
		},
		{
			name:     "empty object",
			val:      cty.EmptyObjectVal,
			expected: false,
		},
		{
			name:     "nil value",
			val:      cty.NilVal,
			expected: false,
		},
		{
			name:     "dynamic value",
			val:      cty.DynamicVal,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isNotEmptyObject(tt.val))
		})
	}
}

func TestReplace(t *testing.T) {
	t.Run("replacement of an existing value", func(t *testing.T) {
		underlying := &hcl.EvalContext{}
		ctx := NewContext(underlying, nil)
		ctx.SetByDot(cty.StringVal("some-value"), "my.value")
		require.NotEqual(t, cty.NilVal, ctx.GetByDot("my.value"))
		ctx.Replace(cty.NumberIntVal(-1), "my.value")
		assert.Equal(t, cty.NumberIntVal(-1), ctx.GetByDot("my.value"))
	})

	t.Run("replacement of a non-existing value", func(t *testing.T) {
		underlying := &hcl.EvalContext{}
		ctx := NewContext(underlying, nil)
		ctx.Replace(cty.NumberIntVal(-1), "my.value")
		assert.Equal(t, cty.NumberIntVal(-1), ctx.GetByDot("my.value"))
	})

	t.Run("empty path", func(t *testing.T) {
		underlying := &hcl.EvalContext{}
		ctx := NewContext(underlying, nil)
		ctx.Replace(cty.NumberIntVal(-1), "")
	})
}
