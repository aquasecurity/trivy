package functions

import "strings"

func ToLower(args ...interface{}) interface{} {
	if len(args) != 1 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	return strings.ToLower(input)
}

func ToUpper(args ...interface{}) interface{} {
	if len(args) != 1 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	return strings.ToUpper(input)
}
