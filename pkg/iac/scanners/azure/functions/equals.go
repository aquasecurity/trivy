package functions

func Equals(args ...any) any {
	if len(args) != 2 {
		return false
	}

	slice1, ok := args[0].([]any)
	if ok {
		slice2, ok := args[1].([]any)
		if ok {
			if len(slice1) != len(slice2) {
				return false
			}
			for i := 0; i < len(slice1); i++ {
				if slice1[i] != slice2[i] {
					return false
				}
			}
			return true
		}
	}

	return args[0] == args[1]
}
