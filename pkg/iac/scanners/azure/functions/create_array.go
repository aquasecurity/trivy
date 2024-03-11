package functions

func CreateArray(args ...interface{}) interface{} {
	var result []interface{}
	if len(args) == 0 {
		return result
	}

	result = append(result, args...)
	return result
}
