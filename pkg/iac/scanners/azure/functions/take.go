package functions

func Take(args ...interface{}) interface{} {
	if len(args) != 2 {
		return ""
	}

	count, ok := args[1].(int)
	if !ok {
		return ""
	}
	switch input := args[0].(type) {
	case string:
		if count > len(input) {
			return input
		}
		return input[:count]
	case interface{}:
		switch iType := input.(type) {
		case []int:
			if count > len(iType) {
				return iType
			}
			return iType[:count]
		case []string:
			if count > len(iType) {
				return iType
			}
			return iType[:count]
		case []bool:
			if count > len(iType) {
				return iType
			}
			return iType[:count]
		case []float64:
			if count > len(iType) {
				return iType
			}
			return iType[:count]
		case []interface{}:
			if count > len(iType) {
				return iType
			}
			return iType[:count]
		}
	}

	return ""
}
