package parser

import (
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
