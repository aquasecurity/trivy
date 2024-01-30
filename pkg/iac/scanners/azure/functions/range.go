package functions

func Range(args ...interface{}) interface{} {

	if len(args) != 2 {
		return []interface{}{}
	}

	start, ok := args[0].(int)
	if !ok {
		return []int{}
	}

	count, ok := args[1].(int)
	if !ok {
		return []int{}
	}

	if count > 10000 {
		count = 10000
	}

	result := make([]int, count)

	for i := 0; i < count; i++ {
		result[i] = start + i
	}

	return result
}
