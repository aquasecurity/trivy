package functions

func Empty(args ...interface{}) interface{} {

	if len(args) != 1 {
		return false
	}

	container := args[0]

	switch cType := container.(type) {
	case string:
		return cType == ""
	case map[string]interface{}:
		return len(cType) == 0
	case interface{}:
		switch iType := cType.(type) {
		case []string:
			return len(iType) == 0
		case []bool:
			return len(iType) == 0
		case []int:
			return len(iType) == 0
		case []float64:
			return len(iType) == 0
		case map[string]interface{}:
			return len(iType) == 0
		}

	}

	return false
}
