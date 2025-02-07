package rego

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

type ChecksRunner struct {
	logger         *log.Logger
	namespaces     set.Set[string]
	modules        map[string]*ast.Module
	runtimeValues  *ast.Term
	store          storage.Store
	compiler       *ast.Compiler
	retriever      *MetadataRetriever
	traceWriter    io.Writer
	tracePerResult bool
}

func (s *ChecksRunner) RunChecks(
	ctx context.Context, source types.Source, inputs ...Input,
) (scan.Results, error) {
	var results scan.Results

	for _, module := range s.modules {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		checkResults, err := s.runCheck(ctx, module, source, inputs...)
		if err != nil {
			s.logger.Error(
				"Failed to apply check",
				log.FilePath(module.Package.Location.File),
				log.Err(err),
			)
			continue
		}

		if checkResults != nil {
			results = append(results, checkResults...)
		}
	}

	return results, nil
}

func (s *ChecksRunner) runCheck(
	ctx context.Context, module *ast.Module, sourceType types.Source, inputs ...Input,
) (scan.Results, error) {
	moduleNamespace := getModuleNamespace(module)
	topLevel := strings.SplitN(moduleNamespace, ".", 2)[0]
	if !s.namespaces.Contains(topLevel) {
		return nil, nil
	}

	staticMeta, err := s.retriever.RetrieveMetadata(ctx, module, GetInputsContents(inputs)...)
	if err != nil {
		return nil, fmt.Errorf("retrieve metadata from check: %w", err)
	}

	// skip if check isn't relevant to what is being scanned
	if !isCheckApplicable(sourceType, staticMeta, inputs...) {
		return nil, nil
	}

	var results scan.Results
	usedRules := set.New[string]()

	// all rules
	for _, rule := range module.Rules {
		ruleName := rule.Head.Name.String()
		if usedRules.Contains(ruleName) {
			continue
		}
		usedRules.Append(ruleName)

		if !isEnforcedRule(ruleName) {
			continue
		}

		ruleResults, err := s.applyRule(ctx, moduleNamespace, ruleName, inputs)
		if err != nil {
			s.logger.Error(
				"Error occurred while applying rule from check",
				log.String("rule", ruleName),
				log.FilePath(module.Package.Location.File),
				log.Err(err),
			)
			continue
		}
		ruleResults.SetRule(staticMeta.ToRule())
		results = append(results, ruleResults...)
	}

	return results, nil
}

func isCheckSupportSubtypes(source types.Source) bool {
	return checkTypesWithSubtype.Contains(source)
}

func isCheckApplicable(sourceType types.Source, staticMetadata *StaticMetadata, inputs ...Input) bool {
	if len(staticMetadata.InputOptions.Selectors) == 0 { // check always applies if no selectors
		return true
	}

	for _, selector := range staticMetadata.InputOptions.Selectors {
		if selector.Type != string(sourceType) {
			return false
		}
	}

	if !isCheckSupportSubtypes(sourceType) {
		return true
	}

	for _, input := range inputs {
		if ii, ok := input.Contents.(map[string]any); ok {
			for provider := range ii {
				if !supportedProviders.Contains(provider) {
					continue
				}

				// check metadata for subtype
				for _, s := range staticMetadata.InputOptions.Selectors {
					if checkSubtype(ii, provider, s.Subtypes) {
						return true
					}
				}
			}
		}
	}
	return false
}

func checkSubtype(ii map[string]any, provider string, subTypes []SubType) bool {
	if len(subTypes) == 0 {
		return true
	}

	for _, st := range subTypes {
		switch services := ii[provider].(type) {
		case map[string]any:
			if st.Provider != provider {
				continue
			}
			if _, exists := services[st.Service]; exists {
				return true
			}
		case string: // k8s - logic can be improved
			if strings.EqualFold(services, st.Group) ||
				strings.EqualFold(services, st.Version) ||
				strings.EqualFold(services, st.Kind) {
				return true
			}
		}
	}
	return false
}

func (s *ChecksRunner) applyRule(ctx context.Context, namespace, rule string, inputs []Input) (scan.Results, error) {
	var results scan.Results
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	for _, input := range inputs {
		s.trace("INPUT", input)
		parsedInput, err := parseRawInput(input.Contents)
		if err != nil {
			s.logger.Error("Error occurred while parsing input", log.Err(err))
			continue
		}

		resultSet, traces, err := s.runQuery(ctx, qualified, parsedInput)
		if err != nil {
			return nil, err
		}
		s.trace("RESULTSET", resultSet)
		ruleResults := convertResults(resultSet, input, namespace, rule, traces)
		if len(ruleResults) == 0 { // It passed because we didn't find anything wrong (NOT because it didn't exist)
			var result regoResult
			result.FS = input.FS
			result.Filepath = input.Path
			result.Managed = true
			results.AddPassedRego(namespace, rule, traces, result)
			continue
		}
		results = append(results, ruleResults...)
	}

	return results, nil
}

func (s *ChecksRunner) runQuery(ctx context.Context, query string, input ast.Value) (rego.ResultSet, []string, error) {
	regoOptions := []func(*rego.Rego){
		rego.Query(query),
		rego.Compiler(s.compiler),
		rego.Store(s.store),
		rego.Runtime(s.runtimeValues),
		rego.Trace(s.traceWriter != nil || s.tracePerResult),
	}

	if input != nil {
		regoOptions = append(regoOptions, rego.ParsedInput(input))
	}

	instance := rego.New(regoOptions...)
	resultSet, err := instance.Eval(ctx)
	if err != nil {
		return nil, nil, err
	}

	// we also build a slice of trace lines for per-result tracing - primarily for fanal/trivy
	var traces []string
	if s.traceWriter != nil {
		rego.PrintTrace(s.traceWriter, instance)
	}

	if s.tracePerResult {
		var buf bytes.Buffer
		rego.PrintTrace(&buf, instance)
		traces = strings.Split(buf.String(), "\n")
	}
	return resultSet, traces, nil
}

func (s *ChecksRunner) trace(heading string, input any) {
	if s.traceWriter == nil {
		return
	}
	data, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		s.logger.Debug("Failed to marshal trace data", log.Err(err))
		return
	}
	fmt.Fprintf(s.traceWriter, "REGO %[1]s:\n%s\nEND REGO %[1]s\n\n", heading, string(data))
}

func parseRawInput(input any) (ast.Value, error) {
	if err := util.RoundTrip(&input); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(input)
}

func isEnforcedRule(name string) bool {
	return name == "deny" || strings.HasPrefix(name, "deny_")
}
