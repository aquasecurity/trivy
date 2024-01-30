package functions

import "strings"

func Trim(args ...interface{}) interface{} {
	if len(args) != 1 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(input)
}
