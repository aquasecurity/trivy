package parser

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/config"
	"github.com/nikolalohinski/gonja/v2/exec"
	"github.com/nikolalohinski/gonja/v2/loaders"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

var gonjaConfig *config.Config
var gonjaEnv *exec.Environment

// TODO: implement support for a subset of popular Ansible filter plugins.
// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/index.html#filter-plugins
// Example: see dirnameFilter for how the "dirname" filter is implemented.
func init() {
	gonjaConfig = gonja.DefaultConfig.Inherit()
	gonjaConfig.StrictUndefined = true

	gonjaEnv = gonja.DefaultEnvironment
	gonjaEnv.Filters.Register("dirname", dirnameFilter)
}

// TODO: add support for a subset of popular Ansible lookup plugins.
// Reference: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/index.html#lookup-plugins
//
// Examples: "template" lookup, "vars" lookup.
//
// Idea: register lookup plugins in the execution context as functions,
// and then use this context as a parent context
//
//	ectx := exec.NewContext(map[string]any{
//		"lookup": func(args *exec.VarArgs) (any, error) {
//			...
//			if args.Args[0].String() == "template" {
//				// read and evaluate template
//			}
//
//			...
//			return nil, fmt.Errorf("unsupported lookup plugin %s", args.Args[0].String())
//		},
//	})

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
	tpl, err := newTemplate(input)
	if err != nil {
		return "", xerrors.Errorf("init template: %w", err)
	}

	var buf bytes.Buffer

	if err := tpl.Execute(&buf, exec.NewContext(variables.ToPlain())); err != nil {
		return "", xerrors.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// newTemplate creates a new template. This function is similar to [gonja.FromBytes],
// but applies a custom configuration.
func newTemplate(input string) (*exec.Template, error) {
	rootID := fmt.Sprintf("root-%s", string(sha256.New().Sum([]byte(input))))

	loader, err := loaders.NewFileSystemLoader("")
	if err != nil {
		return nil, xerrors.Errorf("create fs loader: %w", err)
	}

	shiftedLoader, err := loaders.NewShiftedLoader(rootID, strings.NewReader(input), loader)
	if err != nil {
		return nil, xerrors.Errorf("create shifted loader: %w", err)
	}

	tpl, err := exec.NewTemplate(rootID, gonjaConfig, shiftedLoader, gonjaEnv)
	if err != nil {
		return nil, xerrors.Errorf("create new template: %w", err)
	}

	return tpl, nil
}

func dirnameFilter(_ *exec.Evaluator, in *exec.Value, params *exec.VarArgs) *exec.Value {
	if in == nil {
		return exec.ValueError(errors.New("input value is nil"))
	}

	if params != nil && len(params.Args) > 0 {
		return exec.ValueError(errors.New("no parameters allowed"))
	}

	switch val := in.Val.Interface().(type) {
	case fsutils.FileSource:
		return exec.AsSafeValue(val.Dir())
	default:
		return exec.ValueError(fmt.Errorf("unsupported type %T", in.Val.Interface()))
	}
}
