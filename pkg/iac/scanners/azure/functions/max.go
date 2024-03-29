package functions

func Max(args ...interface{}) interface{} {
	switch args[0].(type) {
	case int:
		var ints []int
		for _, arg := range args {
			ints = append(ints, arg.(int))
		}
		return maxInt(ints)
	case interface{}:
		if iType, ok := args[0].([]int); ok {
			return maxInt(iType)
		}
	}
	return 0
}

func maxInt(args []int) int {
	if len(args) == 0 {
		return 0
	}

	max := args[0]

	for i := 1; i < len(args); i++ {
		if args[i] > max {
			max = args[i]
		}
	}
	return max
}
