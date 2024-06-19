package functions

func Empty(args ...any) any {

	if len(args) != 1 {
		return false
	}

	container := args[0]

	switch cType := container.(type) {
	case string:
		return cType == ""
	case map[string]any:
		return len(cType) == 0
	case any:
		switch iType := cType.(type) {
		case []string:
			return len(iType) == 0
		case []bool:
			return len(iType) == 0
		case []int:
			return len(iType) == 0
		case []float64:
			return len(iType) == 0
		case map[string]any:
			return len(iType) == 0
		}

	}

	return false
}
