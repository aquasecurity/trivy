package functions

import "strings"

func Replace(args ...interface{}) interface{} {
	if len(args) != 3 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	old, ok := args[1].(string)
	if !ok {
		return ""
	}

	new, ok := args[2].(string)
	if !ok {
		return ""
	}

	return strings.ReplaceAll(input, old, new)
}
