package functions

func CreateArray(args ...any) any {
	var result []any
	if len(args) == 0 {
		return result
	}

	result = append(result, args...)
	return result
}
