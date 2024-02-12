package functions

func Array(args ...interface{}) interface{} {

	if len(args) != 1 {
		return ""
	}

	switch ctype := args[0].(type) {
	case int:
		return []int{ctype}
	case string:
		return []string{ctype}
	case map[string]interface{}:
		var result []interface{}
		for k, v := range ctype {
			result = append(result, k, v)
		}
		return result
	case interface{}:
		switch ctype := ctype.(type) {
		case []string:
			return ctype
		case []interface{}:
			return ctype
		}
	}
	return []interface{}{}
}
