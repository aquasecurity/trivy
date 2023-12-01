package functions

import "sort"

func Union(args ...interface{}) interface{} {
	if len(args) == 0 {
		return []interface{}{}
	}
	if len(args) == 1 {
		return args[0]
	}

	switch args[0].(type) {
	case map[string]interface{}:
		return unionMap(args...)
	case interface{}:
		return unionArray(args...)
	}

	return []interface{}{}

}

func unionMap(args ...interface{}) interface{} {
	result := make(map[string]interface{})

	for _, arg := range args {
		switch iType := arg.(type) {
		case map[string]interface{}:
			for k, v := range iType {
				result[k] = v
			}
		}
	}

	return result
}

func unionArray(args ...interface{}) interface{} {
	result := []interface{}{}
	union := make(map[interface{}]bool)

	for _, arg := range args {
		switch iType := arg.(type) {
		case []interface{}:
			for _, item := range iType {
				union[item] = true
			}
		}
	}

	for k := range union {
		result = append(result, k)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].(string) < result[j].(string)
	})

	return result
}
