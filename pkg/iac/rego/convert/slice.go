package convert

import (
	"reflect"
)

func SliceToRego(inputValue reflect.Value) []any {

	// make sure we have a struct literal
	for inputValue.Type().Kind() == reflect.Ptr {
		if inputValue.IsNil() {
			return nil
		}
		inputValue = inputValue.Elem()
	}
	if inputValue.Type().Kind() != reflect.Slice {
		panic("not a slice")
	}

	output := make([]any, inputValue.Len())

	for i := 0; i < inputValue.Len(); i++ {
		val := inputValue.Index(i)
		if val.Type().Kind() == reflect.Ptr && val.IsZero() {
			output[i] = nil
			continue
		}
		output[i] = anonymousToRego(val)
	}

	return output
}
