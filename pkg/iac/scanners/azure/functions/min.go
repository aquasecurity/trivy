package functions

func Min(args ...interface{}) interface{} {
	switch args[0].(type) {
	case int:
		var ints []int
		for _, arg := range args {
			ints = append(ints, arg.(int))
		}
		return minInt(ints)
	case interface{}:
		if iType, ok := args[0].([]int); ok {
			return minInt(iType)
		}
	}
	return 0
}

func minInt(args []int) int {
	if len(args) == 0 {
		return 0
	}

	min := args[0]

	for i := 1; i < len(args); i++ {
		if args[i] < min {
			min = args[i]
		}
	}
	return min
}
