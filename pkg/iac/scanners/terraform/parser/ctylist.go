package parser

import "github.com/zclconf/go-cty/cty"

// insertTupleElement inserts a value into a tuple at the specified index.
// If the idx is outside the bounds of the list, it grows the tuple to
// the new size, and fills in `cty.NilVal` for the missing elements.
func insertTupleElement(list cty.Value, idx int, val cty.Value) cty.Value {
	if list.IsNull() {
		// no null lists
		list = cty.EmptyTupleVal
	}

	newList := make([]cty.Value, max(idx+1, list.LengthInt()))
	for i := 0; i < len(newList); i++ {
		newList[i] = cty.NilVal // Always insert a nil by default

		if i < list.LengthInt() { // keep the original
			newList[i] = list.Index(cty.NumberIntVal(int64(i)))
		}

		if i == idx { // add the new value
			newList[i] = val
		}
	}

	return cty.TupleVal(newList)
}
