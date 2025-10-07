package functions

func Greater(args ...any) any {

	if len(args) != 2 {
		return false
	}

	switch arg0 := args[0].(type) {
	case int:
		arg1, ok := args[1].(int)
		if ok {
			return arg0 > arg1
		}
	case string:
		arg1, ok := args[1].(string)
		if ok {
			return arg0 > arg1
		}
	}

	return false
}

func GreaterOrEquals(args ...any) any {

	if len(args) != 2 {
		return false
	}

	switch arg0 := args[0].(type) {
	case nil:
		return args[1] == nil
	case int:
		arg1, ok := args[1].(int)
		if ok {
			return arg0 >= arg1
		}
	case string:
		arg1, ok := args[1].(string)
		if ok {
			return arg0 >= arg1
		}
	}

	return false
}
