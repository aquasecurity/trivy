package functions

func Mod(args ...any) any {
	if len(args) != 2 {
		return 0
	}

	if a, ok := args[0].(int); ok {
		if b, ok := args[1].(int); ok {
			return a % b
		}
	}
	return 0
}
