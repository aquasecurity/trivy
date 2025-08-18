package parser

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func evaluateTemplate(input string, variables vars.Vars) (string, error) {
	// TODO: Use a real template engine and expand variables
	// Example (simplified): replace {{var }} with vars["var"] (if any)
	for k, v := range variables {
		placeholder := "{{ " + k + " }}"
		input = strings.ReplaceAll(input, placeholder, v.(string))
	}
	return input, nil
}

var templateRe = regexp.MustCompile(`(?m)^(\s*[^:\s]+(\s*):\s*)(\{\{.*\}\})(.*)$`)

// wrapTemplatesQuotes wraps {{ ... }} templates in quotes.
// This is necessary because YAML parsers fail on unquoted {{ ... }} expressions,
// so we temporarily quote them to allow successful parsing.
// TODO: find a more reliable and efficient way to handle templates in YAML.
func wrapTemplatesQuotes(yamlStr string) string {
	return templateRe.ReplaceAllStringFunc(yamlStr, func(line string) string {
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			return line
		}

		key := line[:colonIdx+1]
		val := line[colonIdx+1:]

		trimmed := strings.Trim(val, " \t")
		if !strings.HasPrefix(trimmed, `"`) && !strings.HasPrefix(trimmed, `'`) {
			val = strings.Replace(val, trimmed, `"`+trimmed+`"`, 1)
		}

		return key + val
	})
}
