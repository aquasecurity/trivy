package functions

import "sort"

func Intersection(args ...interface{}) interface{} {

	if args == nil || len(args) < 2 {
		return []interface{}{}
	}

	switch args[0].(type) {
	case map[string]interface{}:
		return intersectionMap(args...)
	case interface{}:
		return intersectionArray(args...)
	}

	return []interface{}{}
}

func intersectionArray(args ...interface{}) interface{} {
	var result []interface{}
	hash := make(map[interface{}]bool)

	for _, arg := range args[0].([]interface{}) {
		hash[arg] = true
	}

	for i := 1; i < len(args); i++ {
		workingHash := make(map[interface{}]bool)
		argArr, ok := args[i].([]interface{})
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

func intersectionMap(args ...interface{}) interface{} {
	hash := make(map[string]interface{})

	for k, v := range args[0].(map[string]interface{}) {
		hash[k] = v
	}

	for i := 1; i < len(args); i++ {
		workingHash := make(map[string]interface{})
		argArr, ok := args[i].(map[string]interface{})
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
