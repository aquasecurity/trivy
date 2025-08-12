package parser

import "strings"

func evaluateTemplate(input string, vars Vars) (string, error) {
	// TODO: Use a real template engine and expand variables
	// Example (simplified): replace {{var }} with vars["var"] (if any)
	for k, v := range vars {
		placeholder := "{{ " + k + " }}"
		input = strings.ReplaceAll(input, placeholder, v.(string))
	}
	return input, nil
}
