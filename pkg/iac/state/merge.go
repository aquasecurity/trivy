package state

import (
	"reflect"
)

// Merge merges the states of the services that have been scanned into a single state.
// if a service has data on both a and b, the service data from b will be preferred.
func (a *State) Merge(b *State) (*State, error) {
	var output State

	aVal := reflect.ValueOf(a).Elem()
	bVal := reflect.ValueOf(b).Elem()
	outputVal := reflect.ValueOf(&output).Elem()

	stateType := reflect.ValueOf(a).Elem().Type()
	for i := 0; i < stateType.NumField(); i++ {
		field := stateType.Field(i)
		if !field.IsExported() {
			continue
		}
		if field.Type.Kind() != reflect.Struct {
			continue
		}
		for j := 0; j < field.Type.NumField(); j++ {
			serviceField := field.Type.Field(j)
			if !serviceField.IsExported() {
				continue
			}
			if serviceField.Type.Kind() != reflect.Struct {
				continue
			}
			if !bVal.Field(i).Field(j).IsZero() {
				outputVal.Field(i).Field(j).Set(bVal.Field(i).Field(j))
			} else {
				outputVal.Field(i).Field(j).Set(aVal.Field(i).Field(j))
			}
		}
	}

	normalised := outputVal.Interface().(State)
	return &normalised, nil
}
