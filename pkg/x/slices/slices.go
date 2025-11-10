package slices

// ZeroToNil returns nil, if slice is empty
func ZeroToNil[T any](t []T) []T {
	if len(t) == 0 {
		return nil
	}
	return t
}
