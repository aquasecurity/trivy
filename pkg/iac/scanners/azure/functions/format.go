package functions

import (
	"fmt"
	"strings"
)

func Format(args ...interface{}) interface{} {
	formatter := generateFormatterString(args...)

	return fmt.Sprintf(formatter, args[1:]...)
}

func generateFormatterString(args ...interface{}) string {

	formatter, ok := args[0].(string)
	if !ok {
		return ""
	}
	for i, arg := range args[1:] {
		switch arg.(type) {
		case string:
			formatter = strings.ReplaceAll(formatter, fmt.Sprintf("{%d}", i), "%s")
		case int, int32, int64, uint, uint32, uint64:
			formatter = strings.ReplaceAll(formatter, fmt.Sprintf("{%d}", i), "%d")
		case float64, float32:
			formatter = strings.ReplaceAll(formatter, fmt.Sprintf("{%d}", i), "%f")
		}
	}
	return formatter
}
