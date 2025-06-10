package parser

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func Test_insertTupleElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		start cty.Value
		index int
		value cty.Value
		want  cty.Value
	}{
		{
			name:  "empty",
			start: cty.Value{},
			index: 0,
			value: cty.NilVal,
			want:  cty.TupleVal([]cty.Value{cty.NilVal}),
		},
		{
			name:  "empty to length",
			start: cty.Value{},
			index: 2,
			value: cty.NilVal,
			want:  cty.TupleVal([]cty.Value{cty.NilVal, cty.NilVal, cty.NilVal}),
		},
		{
			name:  "insert to empty",
			start: cty.EmptyTupleVal,
			index: 1,
			value: cty.NumberIntVal(5),
			want:  cty.TupleVal([]cty.Value{cty.NilVal, cty.NumberIntVal(5)}),
		},
		{
			name:  "insert to existing",
			start: cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2), cty.NumberIntVal(3)}),
			index: 1,
			value: cty.NumberIntVal(5),
			want:  cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(5), cty.NumberIntVal(3)}),
		},
		{
			name:  "insert to existing, extends",
			start: cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2), cty.NumberIntVal(3)}),
			index: 4,
			value: cty.NumberIntVal(5),
			want: cty.TupleVal([]cty.Value{
				cty.NumberIntVal(1), cty.NumberIntVal(2),
				cty.NumberIntVal(3), cty.NilVal,
				cty.NumberIntVal(5),
			}),
		},
		{
			name:  "mixed list",
			start: cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.NumberIntVal(2), cty.NumberIntVal(3)}),
			index: 1,
			value: cty.BoolVal(true),
			want: cty.TupleVal([]cty.Value{
				cty.StringVal("a"), cty.BoolVal(true), cty.NumberIntVal(3),
			}),
		},
		{
			name:  "replace end",
			start: cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.NumberIntVal(2), cty.NumberIntVal(3)}),
			index: 2,
			value: cty.StringVal("end"),
			want: cty.TupleVal([]cty.Value{
				cty.StringVal("a"), cty.NumberIntVal(2), cty.StringVal("end"),
			}),
		},

		// Some bad arguments
		{
			name:  "negative index",
			start: cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.NumberIntVal(2), cty.NumberIntVal(3)}),
			index: -1,
			value: cty.BoolVal(true),
			want:  cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.NumberIntVal(2), cty.NumberIntVal(3)}),
		},
		{
			name:  "non-list",
			start: cty.BoolVal(true),
			index: 1,
			value: cty.BoolVal(true),
			want:  cty.TupleVal([]cty.Value{cty.NilVal, cty.BoolVal(true)}),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, insertTupleElement(tt.start, tt.index, tt.value))
		})
	}
}
