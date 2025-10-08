package functions

import "strconv"

func Int(args ...any) any {
	if len(args) != 1 {
		return 0
	}
	if a, ok := args[0].(int); ok {
		return a
	}
	if a, ok := args[0].(string); ok {
		i, err := strconv.Atoi(a)
		if err != nil {
			return 0
		}
		return i
	}
	return 0
}
