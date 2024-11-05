package functions

func Or(args ...any) any {

	if len(args) <= 1 {
		return false
	}

	for _, arg := range args {
		arg1, ok := arg.(bool)
		if !ok {
			return false
		}
		if arg1 {
			return true
		}

	}
	return false
}
