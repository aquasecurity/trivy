package functions

import (
	"fmt"
)

func Concat(args ...any) any {

	switch args[0].(type) {
	case string:
		var result string
		for _, arg := range args {
			result += fmt.Sprintf("%v", arg)
		}
		return result
	case any:
		var result []any
		for _, arg := range args {
			argArr, ok := arg.([]any)
			if !ok {
				continue
			}
			result = append(result, argArr...)
		}
		return result
	}
	return ""
}
