package functions

import "fmt"

func String(args ...any) any {
	if len(args) != 1 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return fmt.Sprintf("%v", args[0])
	}

	return input
}
