package functions

func Skip(args ...any) any {
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
			return ""
		}
		return input[count:]
	case any:
		switch iType := input.(type) {
		case []int:
			return iType[count:]
		case []string:
			return iType[count:]
		case []bool:
			return iType[count:]
		case []float64:
			return iType[count:]
		case []any:
			return iType[count:]
		}
	}

	return ""
}
