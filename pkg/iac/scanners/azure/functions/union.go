package functions

import "sort"

func Union(args ...any) any {
	if len(args) == 0 {
		return []any{}
	}
	if len(args) == 1 {
		return args[0]
	}

	switch args[0].(type) {
	case map[string]any:
		return unionMap(args...)
	case any:
		return unionArray(args...)
	}

	return []any{}

}

func unionMap(args ...any) any {
	result := make(map[string]any)

	for _, arg := range args {
		if iType, ok := arg.(map[string]any); ok {
			for k, v := range iType {
				result[k] = v
			}
		}
	}

	return result
}

func unionArray(args ...any) any {
	var result []any
	union := make(map[any]bool)

	for _, arg := range args {
		if iType, ok := arg.([]any); ok {
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
