package rego

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/rego/schemas"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var checkTypesWithSubtype = map[types.Source]struct{}{
	types.SourceCloud:      {},
	types.SourceDefsec:     {},
	types.SourceKubernetes: {},
}

var supportedProviders = makeSupportedProviders()

func makeSupportedProviders() map[string]struct{} {
	m := make(map[string]struct{})
	for _, p := range providers.AllProviders() {
		m[string(p)] = struct{}{}
	}
	m["kind"] = struct{}{} // kubernetes
	return m
}

var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	ruleNamespaces          map[string]struct{}
	policies                map[string]*ast.Module
	store                   storage.Store
	dataDirs                []string
	runtimeValues           *ast.Term
	compiler                *ast.Compiler
	regoErrorLimit          int
	debug                   debug.Logger
	traceWriter             io.Writer
	tracePerResult          bool
	retriever               *MetadataRetriever
	policyFS                fs.FS
	dataFS                  fs.FS
	frameworks              []framework.Framework
	spec                    string
	inputSchema             any // unmarshalled into this from a json schema document
	sourceType              types.Source
	includeDeprecatedChecks bool

	embeddedLibs   map[string]*ast.Module
	embeddedChecks map[string]*ast.Module
}

func (s *Scanner) SetIncludeDeprecatedChecks(b bool) {
	s.includeDeprecatedChecks = b
}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	// handled externally
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) SetRegoOnly(bool) {}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	// handled externally
}

func (s *Scanner) trace(heading string, input any) {
	if s.traceWriter == nil {
		return
	}
	data, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(s.traceWriter, "REGO %[1]s:\n%s\nEND REGO %[1]s\n\n", heading, string(data))
}

func (s *Scanner) SetPolicyFilesystem(fsys fs.FS) {
	s.policyFS = fsys
}

func (s *Scanner) SetDataFilesystem(fsys fs.FS) {
	s.dataFS = fsys
}

func (s *Scanner) SetPolicyReaders(_ []io.Reader) {
	// NOTE: Policy readers option not applicable for rego, policies are loaded on-demand by other scanners.
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "rego", "scanner")
}

func (s *Scanner) SetTraceWriter(writer io.Writer) {
	s.traceWriter = writer
}

func (s *Scanner) SetPerResultTracingEnabled(b bool) {
	s.tracePerResult = b
}

func (s *Scanner) SetPolicyDirs(_ ...string) {
	// NOTE: Policy dirs option not applicable for rego, policies are loaded on-demand by other scanners.
}

func (s *Scanner) SetDataDirs(dirs ...string) {
	s.dataDirs = dirs
}

func (s *Scanner) SetPolicyNamespaces(namespaces ...string) {
	for _, namespace := range namespaces {
		s.ruleNamespaces[namespace] = struct{}{}
	}
}

func (s *Scanner) SetSkipRequiredCheck(_ bool) {
	// NOTE: Skip required option not applicable for rego.
}

func (s *Scanner) SetRegoErrorLimit(limit int) {
	s.regoErrorLimit = limit
}

type DynamicMetadata struct {
	Warning   bool
	Filepath  string
	Message   string
	StartLine int
	EndLine   int
}

func NewScanner(source types.Source, opts ...options.ScannerOption) *Scanner {
	schema, ok := schemas.SchemaMap[source]
	if !ok {
		schema = schemas.Anything
	}

	s := &Scanner{
		regoErrorLimit: ast.CompileErrorLimitDefault,
		sourceType:     source,
		ruleNamespaces: make(map[string]struct{}),
		runtimeValues:  addRuntimeValues(),
	}

	maps.Copy(s.ruleNamespaces, builtinNamespaces)

	for _, opt := range opts {
		opt(s)
	}
	if schema != schemas.None {
		err := json.Unmarshal([]byte(schema), &s.inputSchema)
		if err != nil {
			panic(err)
		}
	}
	return s
}

func (s *Scanner) SetParentDebugLogger(l debug.Logger) {
	s.debug = l.Extend("rego")
}

func (s *Scanner) runQuery(ctx context.Context, query string, input ast.Value, disableTracing bool) (rego.ResultSet, []string, error) {

	trace := (s.traceWriter != nil || s.tracePerResult) && !disableTracing

	regoOptions := []func(*rego.Rego){
		rego.Query(query),
		rego.Compiler(s.compiler),
		rego.Store(s.store),
		rego.Runtime(s.runtimeValues),
		rego.Trace(trace),
	}

	if s.inputSchema != nil {
		schemaSet := ast.NewSchemaSet()
		schemaSet.Put(ast.MustParseRef("schema.input"), s.inputSchema)
		regoOptions = append(regoOptions, rego.Schemas(schemaSet))
	}

	if input != nil {
		regoOptions = append(regoOptions, rego.ParsedInput(input))
	}

	instance := rego.New(regoOptions...)
	set, err := instance.Eval(ctx)
	if err != nil {
		return nil, nil, err
	}

	// we also build a slice of trace lines for per-result tracing - primarily for fanal/trivy
	var traces []string

	if trace {
		if s.traceWriter != nil {
			rego.PrintTrace(s.traceWriter, instance)
		}
		if s.tracePerResult {
			traceBuffer := bytes.NewBuffer([]byte{})
			rego.PrintTrace(traceBuffer, instance)
			traces = strings.Split(traceBuffer.String(), "\n")
		}
	}
	return set, traces, nil
}

type Input struct {
	Path     string `json:"path"`
	FS       fs.FS  `json:"-"`
	Contents any    `json:"contents"`
}

func GetInputsContents(inputs []Input) []any {
	results := make([]any, len(inputs))
	for i, c := range inputs {
		results[i] = c.Contents
	}
	return results
}

func (s *Scanner) ScanInput(ctx context.Context, inputs ...Input) (scan.Results, error) {

	s.debug.Log("Scanning %d inputs...", len(inputs))

	var results scan.Results

	for _, module := range s.policies {

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		namespace := getModuleNamespace(module)
		topLevel := strings.Split(namespace, ".")[0]
		if _, ok := s.ruleNamespaces[topLevel]; !ok {
			continue
		}

		staticMeta, err := s.retriever.RetrieveMetadata(ctx, module, GetInputsContents(inputs)...)
		if err != nil {
			s.debug.Log(
				"Error occurred while retrieving metadata from check %q: %s",
				module.Package.Location.File, err)
			continue
		}

		if !s.includeDeprecatedChecks && staticMeta.Deprecated {
			continue // skip deprecated checks
		}

		if isPolicyWithSubtype(s.sourceType) {
			// skip if check isn't relevant to what is being scanned
			if !isPolicyApplicable(staticMeta, inputs...) {
				continue
			}
		}

		if len(inputs) == 0 {
			continue
		}

		usedRules := make(map[string]struct{})

		// all rules
		for _, rule := range module.Rules {
			ruleName := rule.Head.Name.String()
			if _, ok := usedRules[ruleName]; ok {
				continue
			}
			usedRules[ruleName] = struct{}{}
			if isEnforcedRule(ruleName) {
				ruleResults, err := s.applyRule(ctx, namespace, ruleName, inputs, staticMeta.InputOptions.Combined)
				if err != nil {
					s.debug.Log(
						"Error occurred while applying rule %q from check %q: %s",
						ruleName, module.Package.Location.File, err)
					continue
				}
				results = append(results, s.embellishResultsWithRuleMetadata(ruleResults, *staticMeta)...)
			}
		}

	}

	return results, nil
}

func isPolicyWithSubtype(sourceType types.Source) bool {
	_, exists := checkTypesWithSubtype[sourceType]
	return exists
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

func isPolicyApplicable(staticMetadata *StaticMetadata, inputs ...Input) bool {
	for _, input := range inputs {
		if ii, ok := input.Contents.(map[string]any); ok {
			for provider := range ii {
				if _, exists := supportedProviders[provider]; !exists {
					continue
				}

				if len(staticMetadata.InputOptions.Selectors) == 0 { // check always applies if no selectors
					return true
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

func parseRawInput(input any) (ast.Value, error) {
	if err := util.RoundTrip(&input); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(input)
}

func (s *Scanner) applyRule(ctx context.Context, namespace, rule string, inputs []Input, combined bool) (scan.Results, error) {

	// handle combined evaluations if possible
	if combined {
		s.trace("INPUT", inputs)
		return s.applyRuleCombined(ctx, namespace, rule, inputs)
	}

	var results scan.Results
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	for _, input := range inputs {
		s.trace("INPUT", input)
		parsedInput, err := parseRawInput(input.Contents)
		if err != nil {
			s.debug.Log("Error occurred while parsing input: %s", err)
			continue
		}
		if ignored, err := s.isIgnored(ctx, namespace, rule, parsedInput); err != nil {
			return nil, err
		} else if ignored {
			var result regoResult
			result.FS = input.FS
			result.Filepath = input.Path
			result.Managed = true
			results.AddIgnored(result)
			continue
		}
		set, traces, err := s.runQuery(ctx, qualified, parsedInput, false)
		if err != nil {
			return nil, err
		}
		s.trace("RESULTSET", set)
		ruleResults := s.convertResults(set, input, namespace, rule, traces)
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

func (s *Scanner) applyRuleCombined(ctx context.Context, namespace, rule string, inputs []Input) (scan.Results, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	parsed, err := parseRawInput(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse input: %w", err)
	}

	var results scan.Results

	if ignored, err := s.isIgnored(ctx, namespace, rule, parsed); err != nil {
		return nil, err
	} else if ignored {
		for _, input := range inputs {
			var result regoResult
			result.FS = input.FS
			result.Filepath = input.Path
			result.Managed = true
			results.AddIgnored(result)
		}
		return results, nil
	}
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	set, traces, err := s.runQuery(ctx, qualified, parsed, false)
	if err != nil {
		return nil, err
	}
	return s.convertResults(set, inputs[0], namespace, rule, traces), nil
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
