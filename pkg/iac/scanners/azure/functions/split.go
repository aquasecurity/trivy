package functions

import "strings"

func Split(args ...any) any {
	if len(args) != 2 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	switch separator := args[1].(type) {
	case string:
		return strings.Split(input, separator)
	case any:
		if separator, ok := separator.([]string); ok {
			m := make(map[rune]int)
			for _, r := range separator {
				r := rune(r[0])
				m[r] = 1
			}

			splitter := func(r rune) bool {
				return m[r] == 1
			}

			return strings.FieldsFunc(input, splitter)
		}

	}
	return []string{}
}
