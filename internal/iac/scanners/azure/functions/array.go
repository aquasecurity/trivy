package functions

func Array(args ...any) any {

	if len(args) != 1 {
		return ""
	}

	switch ctype := args[0].(type) {
	case int:
		return []int{ctype}
	case string:
		return []string{ctype}
	case map[string]any:
		var result []any
		for k, v := range ctype {
			result = append(result, k, v)
		}
		return result
	case any:
		switch ctype := ctype.(type) {
		case []string:
			return ctype
		case []any:
			return ctype
		}
	}
	return []any{}
}
