package functions

func First(args ...interface{}) interface{} {
	if len(args) != 1 {
		return ""
	}

	container := args[0]

	switch cType := container.(type) {
	case string:
		if len(cType) > 0 {
			return string(cType[0])
		}
	case interface{}:
		switch iType := cType.(type) {
		case []string:
			if len(iType) > 0 {
				return iType[0]
			}
		case []bool:
			if len(iType) > 0 {
				return iType[0]
			}
		case []int:
			if len(iType) > 0 {
				return iType[0]
			}
		case []float64:
			if len(iType) > 0 {
				return iType[0]
			}
		}
	}

	return ""
}
