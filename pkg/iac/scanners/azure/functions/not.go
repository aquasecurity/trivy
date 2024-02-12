package functions

func Not(args ...interface{}) interface{} {

	if len(args) != 1 {
		return false
	}

	if condition, ok := args[0].(bool); ok {
		return !condition
	}
	return false
}
