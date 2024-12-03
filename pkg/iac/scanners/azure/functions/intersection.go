package functions

import "sort"

func Intersection(args ...any) any {

	if args == nil || len(args) < 2 {
		return []any{}
	}

	switch args[0].(type) {
	case map[string]any:
		return intersectionMap(args...)
	case any:
		return intersectionArray(args...)
	}

	return []any{}
}

func intersectionArray(args ...any) any {
	var result []any
	hash := make(map[any]bool)

	for _, arg := range args[0].([]any) {
		hash[arg] = true
	}

	for i := 1; i < len(args); i++ {
		workingHash := make(map[any]bool)
		argArr, ok := args[i].([]any)
		if !ok {
			continue
		}
		for _, item := range argArr {
			if _, ok := hash[item]; ok {
				workingHash[item] = true
			}
		}
		hash = workingHash
	}

	for k := range hash {
		result = append(result, k)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].(string) < result[j].(string)
	})

	return result
}

func intersectionMap(args ...any) any {
	hash := make(map[string]any)

	for k, v := range args[0].(map[string]any) {
		hash[k] = v
	}

	for i := 1; i < len(args); i++ {
		workingHash := make(map[string]any)
		argArr, ok := args[i].(map[string]any)
		if !ok {
			continue
		}
		for k, v := range argArr {
			if ev, ok := hash[k]; ok && ev == v {
				workingHash[k] = v
			}
		}
		hash = workingHash
	}

	return hash
}
