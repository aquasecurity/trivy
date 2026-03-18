package functions

import (
	"fmt"
	"strings"
)

func Concat(args ...any) any {

	switch args[0].(type) {
	case string:
		var sb strings.Builder
		for _, arg := range args {
			fmt.Fprintf(&sb, "%v", arg)
		}
		return sb.String()
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
