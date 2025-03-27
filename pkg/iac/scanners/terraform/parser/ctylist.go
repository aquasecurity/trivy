package parser

import "github.com/zclconf/go-cty/cty"

// insertTupleElement inserts a value into a tuple at the specified index.
// If the idx is outside the bounds of the list, it grows the tuple to
// the new size, and fills in `cty.NilVal` for the missing elements.
//
// This function will not panic. If the list value is not a list, it will
// be replaced with an empty list.
func insertTupleElement(list cty.Value, idx int, val cty.Value) cty.Value {
	if list.IsNull() || !list.Type().IsTupleType() {
		// better than a panic
		list = cty.EmptyTupleVal
	}

	if idx < 0 {
		// Nothing to do?
		return list
	}

	// Create a new list of the correct length, copying in the old list
	// values for matching indices.
	newList := make([]cty.Value, max(idx+1, list.LengthInt()))
	for it := list.ElementIterator(); it.Next(); {
		key, elem := it.Element()
		elemIdx, _ := key.AsBigFloat().Int64()
		newList[elemIdx] = elem
	}
	// Insert the new value.
	newList[idx] = val

	return cty.TupleVal(newList)
}
