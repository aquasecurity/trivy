package slices

func Merge[T any](slices ...[]T) []T {
	if len(slices) == 0 {
		return []T{}
	}

	var res []T
	for _, s := range slices {
		res = append(res, s...)
	}

	if len(res) == 0 {
		return []T{}
	}

	return res
}
