package functions

func And(args ...interface{}) interface{} {

	if len(args) <= 1 {
		return false
	}

	arg0, ok := args[0].(bool)
	if !ok {
		return false
	}

	benchmark := arg0

	for _, arg := range args[1:] {
		arg1, ok := arg.(bool)
		if !ok {
			return false
		}
		if benchmark != arg1 {
			return false
		}

	}
	return true
}
