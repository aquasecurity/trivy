package functions

import "strings"

func Join(args ...interface{}) interface{} {

	if len(args) != 2 {
		return ""
	}

	container, ok := args[0].([]string)
	if !ok {
		return ""
	}

	separator, ok := args[1].(string)
	if !ok {
		return ""
	}

	return strings.Join(container, separator)
}
