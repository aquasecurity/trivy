package parser

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/mitsuhiko/minijinja/minijinja-go/v2"
	"github.com/mitsuhiko/minijinja/minijinja-go/v2/value"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

var templateEnv *minijinja.Environment

// TODO: implement support for a subset of popular Ansible filter plugins.
// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/index.html#filter-plugins
// Example: see dirnameFilter for how the "dirname" filter is implemented.
func init() {
	templateEnv = minijinja.NewEnvironment()
	templateEnv.SetUndefinedBehavior(minijinja.UndefinedStrict)
	templateEnv.AddFilter("dirname", dirnameFilter)
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

// evaluateTemplate executes a Jinja2 template with given variables safely.
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

// evaluateTemplateUnsafe evaluates a template with given variables.
func evaluateTemplateUnsafe(input string, variables vars.Vars) (string, error) {
	tpl, err := newTemplate(input)
	if err != nil {
		return "", xerrors.Errorf("init template: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.RenderToWrite(templateCtx{variables.ToPlain()}, &buf); err != nil {
		return "", xerrors.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// newTemplate creates a new template from a string.
func newTemplate(input string) (*minijinja.Template, error) {
	tpl, err := templateEnv.TemplateFromString(input)
	if err != nil {
		return nil, xerrors.Errorf("create template: %w", err)
	}
	return tpl, nil
}

var _ value.MapObject = (*templateCtx)(nil)

// templateCtx wraps a plain vars map and implements value.MapObject so that
// FileSource values are lazily converted to their string path representation
// when accessed by the template engine.
type templateCtx struct{ m map[string]any }

func (c templateCtx) Keys() []string {
	keys := make([]string, 0, len(c.m))
	for k := range c.m {
		keys = append(keys, k)
	}
	return keys
}

func (c templateCtx) GetAttr(name string) value.Value {
	v, ok := c.m[name]
	if !ok {
		return value.Undefined()
	}
	if fs, ok := v.(fsutils.FileSource); ok {
		return value.FromString(fs.String())
	}
	return value.FromAny(v)
}

func dirnameFilter(_ minijinja.FilterState, val minijinja.Value, args []minijinja.Value, _ map[string]minijinja.Value) (minijinja.Value, error) {
	if len(args) > 0 {
		return value.Undefined(), errors.New("dirname: no parameters allowed")
	}
	s, ok := val.AsString()
	if !ok {
		return value.Undefined(), fmt.Errorf("dirname: expected string, got %s", val.Kind())
	}
	return value.FromString(path.Dir(s)), nil
}
