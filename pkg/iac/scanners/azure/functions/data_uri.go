package functions

import (
	"fmt"
	"strings"
)

func DataUri(args ...interface{}) interface{} {
	if len(args) == 0 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	return fmt.Sprintf("data:text/plain;charset=utf8;base64,%s", Base64(input))
}

func DataUriToString(args ...interface{}) interface{} {
	if len(args) == 0 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}
	parts := strings.Split(input, "base64,")
	if len(parts) != 2 {
		return ""
	}

	return Base64ToString(parts[1])
}
