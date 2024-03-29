package functions

import (
	"fmt"
)

func Concat(args ...interface{}) interface{} {

	switch args[0].(type) {
	case string:
		var result string
		for _, arg := range args {
			result += fmt.Sprintf("%v", arg)
		}
		return result
	case interface{}:
		var result []interface{}
		for _, arg := range args {
			argArr, ok := arg.([]interface{})
			if !ok {
				continue
			}
			result = append(result, argArr...)
		}
		return result
	}
	return ""
}
