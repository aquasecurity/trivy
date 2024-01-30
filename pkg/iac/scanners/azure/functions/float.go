package functions

import "strconv"

func Float(args ...interface{}) interface{} {
	if len(args) != 1 {
		return 0.0
	}
	if a, ok := args[0].(int); ok {
		return float64(a)
	}
	if a, ok := args[0].(string); ok {
		f, err := strconv.ParseFloat(a, 64)
		if err != nil {
			return 0.0
		}
		return f
	}
	return 0.0
}
