package functions

import "strings"

func StartsWith(args ...interface{}) interface{} {

	if len(args) != 2 {
		return false
	}

	stringToSearch, ok := args[0].(string)
	if !ok {
		return false
	}

	stringToFind, ok := args[1].(string)
	if !ok {
		return false
	}

	return strings.HasPrefix(stringToSearch, stringToFind)
}
