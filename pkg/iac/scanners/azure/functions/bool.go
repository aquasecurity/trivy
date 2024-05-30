package functions

import "strings"

func Bool(args ...any) any {
	if len(args) != 1 {
		return false
	}

	switch input := args[0].(type) {
	case bool:
		return input
	case string:
		input = strings.ToLower(input)
		return input == "true" || input == "1" || input == "yes" || input == "on"
	case int:
		return input == 1
	}
	return false
}
