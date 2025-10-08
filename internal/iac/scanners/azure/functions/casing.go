package functions

import "strings"

func ToLower(args ...any) any {
	if len(args) != 1 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	return strings.ToLower(input)
}

func ToUpper(args ...any) any {
	if len(args) != 1 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	return strings.ToUpper(input)
}
