package functions

func CreateObject(args ...interface{}) interface{} {
	obj := make(map[string]interface{})
	if len(args) == 0 {
		return obj
	}

	// if there aren't even pairs then return an empty object
	if len(args)%2 != 0 {
		return obj
	}

	for i := 0; i < len(args); i += 2 {
		key := args[i].(string)
		value := args[i+1]
		obj[key] = value
	}

	return obj
}
