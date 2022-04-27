package rego

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/rules"

	"github.com/open-policy-agent/opa/ast"

	"github.com/open-policy-agent/opa/storage"

	"github.com/open-policy-agent/opa/rego"
)

type Scanner struct {
	ruleNamespaces map[string]struct{}
	policies       map[string]*ast.Module
	store          storage.Store
	dataDirs       []string
	runtimeValues  *ast.Term
	compiler       *ast.Compiler
	debugWriter    io.Writer
	retriever      *MetadataRetriever
}

type DynamicMetadata struct {
	Warning   bool
	Filepath  string
	Message   string
	StartLine int
	EndLine   int
}

func NewScanner(options ...Option) *Scanner {
	s := &Scanner{
		ruleNamespaces: map[string]struct{}{
			"appshield": {},
			"defsec":    {},
		},
		runtimeValues: addRuntimeValues(),
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func getModuleNamespace(module *ast.Module) string {
	return strings.TrimPrefix(module.Package.Path.String(), "data.")
}

func (s *Scanner) runQuery(ctx context.Context, query string, input interface{}, disableTracing bool) (rego.ResultSet, error) {

	trace := s.debugWriter != nil && !disableTracing

	options := []func(*rego.Rego){
		rego.Query(query),
		rego.Compiler(s.compiler),
		rego.Store(s.store),
		rego.Runtime(s.runtimeValues),
		rego.Trace(trace),
	}

	if input != nil {
		options = append(options, rego.Input(input))
	}

	instance := rego.New(options...)
	set, err := instance.Eval(ctx)
	if err != nil {
		return nil, err
	}

	if trace {
		rego.PrintTrace(s.debugWriter, instance)
	}
	return set, nil
}

type Input struct {
	Path     string       `json:"path"`
	Contents interface{}  `json:"contents"`
	Type     types.Source `json:"type"`
}

func (s *Scanner) ScanInput(ctx context.Context, inputs ...Input) (rules.Results, error) {

	var results rules.Results
	var filteredInputs []Input

	for _, module := range s.policies {

		namespace := getModuleNamespace(module)
		topLevel := strings.Split(namespace, ".")[0]
		if _, ok := s.ruleNamespaces[topLevel]; !ok {
			continue
		}

		staticMeta, err := s.retriever.RetrieveMetadata(ctx, module)
		if err != nil {
			return nil, err
		}

		if len(staticMeta.InputOptions.Selectors) > 0 {
			filteredInputs = nil
			for _, in := range inputs {
				var match bool
				for _, selector := range staticMeta.InputOptions.Selectors {
					if selector.Type == string(in.Type) {
						match = true
						break
					}
				}
				if match {
					filteredInputs = append(filteredInputs, in)
				}
			}
		} else {
			filteredInputs = make([]Input, len(inputs))
			copy(filteredInputs, inputs)
		}

		// all rules
		for _, rule := range module.Rules {
			ruleName := rule.Head.Name.String()
			if isEnforcedRule(ruleName) {
				ruleResults, err := s.applyRule(ctx, namespace, ruleName, filteredInputs, staticMeta.InputOptions.Combined)
				if err != nil {
					return nil, err
				}
				results = append(results, s.embellishResultsWithRuleMetadata(ruleResults, *staticMeta)...)
			}
		}

	}

	return results, nil
}

func (s *Scanner) applyRule(ctx context.Context, namespace string, rule string, inputs []Input, combined bool) (rules.Results, error) {

	// handle combined evaluations if possible
	if combined {
		return s.applyRuleCombined(ctx, namespace, rule, inputs)
	}

	var results rules.Results
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	for _, input := range inputs {
		if ignored, err := s.isIgnored(ctx, namespace, rule, input); err != nil {
			return nil, err
		} else if ignored {
			var result regoResult
			result.Filepath = input.Path
			results.AddIgnored(result)
			continue
		}
		set, err := s.runQuery(ctx, qualified, input.Contents, false)
		if err != nil {
			return nil, err
		}
		ruleResults := s.convertResults(set, input.Path, namespace, rule)
		if len(ruleResults) == 0 {
			var result regoResult
			result.Filepath = input.Path
			results.AddPassed(result)
			continue
		}
		results = append(results, ruleResults...)
	}

	return results, nil
}

func (s *Scanner) applyRuleCombined(ctx context.Context, namespace string, rule string, inputs []Input) (rules.Results, error) {
	var results rules.Results
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	if ignored, err := s.isIgnored(ctx, namespace, rule, inputs); err != nil {
		return nil, err
	} else if ignored {
		for _, input := range inputs {
			var result regoResult
			result.Filepath = input.Path
			results.AddIgnored(result)
		}
		return results, nil
	}
	set, err := s.runQuery(ctx, qualified, inputs, false)
	if err != nil {
		return nil, err
	}
	return s.convertResults(set, "", namespace, rule), nil
}

// severity is now set with metadata, so deny/warn/violation now behave the same way
func isEnforcedRule(name string) bool {
	switch {
	case name == "deny", strings.HasPrefix(name, "deny_"),
		name == "warn", strings.HasPrefix(name, "warn_"),
		name == "violation", strings.HasPrefix(name, "violation_"):
		return true
	}
	return false
}
