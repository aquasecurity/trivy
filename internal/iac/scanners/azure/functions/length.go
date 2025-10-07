package functions

func Length(args ...any) any {

	if len(args) != 1 {
		return 0
	}

	switch ctype := args[0].(type) {
	case string:
		return len(ctype)
	case map[string]any:
		return len(ctype)
	case any:
		switch iType := ctype.(type) {
		case []string:
			return len(iType)
		case []bool:
			return len(iType)
		case []int:
			return len(iType)
		case []float64:
			return len(iType)
		case []any:
			return len(iType)
		}
	}
	return 0
}
