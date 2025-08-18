package parser

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/exec"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

// evaluateTemplateSafe executes a Gonja template with given variables safely.
// It prevents infinite loops and recovers from panics.
// Added due to infinite loop issue: https://github.com/NikolaLohinski/gonja/issues/52
func evaluateTemplate(input string, variables vars.Vars) (string, error) {
	type result struct {
		res string
		err error
	}

	resultCh := make(chan result, 1)

	// Run the template evaluation in a separate goroutine
	// to prevent infinite loops or long-running evaluation
	go func() {
		// Catch any panic that may occur during template evaluation
		defer func() {
			if r := recover(); r != nil {
				resultCh <- result{"", fmt.Errorf("template evaluation panic: %v", r)}
			}
		}()

		res, err := evaluateTemplateUnsafe(input, variables)
		resultCh <- result{res, err}
	}()

	// Wait for evaluation to finish or timeout after 2 seconds
	timeout := time.Second * 2
	select {
	case r := <-resultCh:
		return r.res, r.err
	case <-time.After(timeout):
		return "", fmt.Errorf("template evaluation timeout after %s", timeout)
	}
}

// evaluateTemplate evaluates a template with given variables.
func evaluateTemplateUnsafe(input string, variables vars.Vars) (string, error) {
	tpl, parseErr := gonja.FromString(input)
	if parseErr != nil {
		return "", xerrors.Errorf("parse template: %w", parseErr)
	}

	var buf bytes.Buffer

	if err := tpl.Execute(&buf, exec.NewContext(variables)); err != nil {
		return "", xerrors.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
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
