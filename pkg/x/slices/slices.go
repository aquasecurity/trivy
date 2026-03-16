package slices

// Map manipulates a slice and transforms it to a slice of another type.
// Unlike lo.Map, the transform function doesn't receive an index argument.
func Map[T, U any](collection []T, transform func(item T) U) []U {
	if len(collection) == 0 {
		return nil
	}
	result := make([]U, len(collection))
	for i := range collection {
		result[i] = transform(collection[i])
	}
	return result
}

// ZeroToNil returns nil, if slice is empty
func ZeroToNil[T any](t []T) []T {
	if len(t) == 0 {
		return nil
	}
	return t
}
