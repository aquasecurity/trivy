package functions

func SubString(args ...any) any {
	if len(args) < 2 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	start, ok := args[1].(int)
	if !ok {
		return ""
	}

	if len(args) == 2 {
		args = append(args, len(input))
	}

	length, ok := args[2].(int)
	if !ok {
		return ""
	}

	if start > len(input) {
		return ""
	}

	if start+length > len(input) {
		return input[start:]
	}

	return input[start : start+length]
}
