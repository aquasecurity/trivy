package functions

func If(args ...any) any {

	if len(args) != 3 {
		return nil
	}

	if condition, ok := args[0].(bool); ok {
		if condition {
			return args[1]
		}
	}
	return args[2]
}
