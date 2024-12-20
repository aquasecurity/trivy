package rego

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/rego/schemas"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

var checkTypesWithSubtype = set.New[types.Source](types.SourceCloud, types.SourceDefsec, types.SourceKubernetes)

var supportedProviders = makeSupportedProviders()

func makeSupportedProviders() set.Set[string] {
	m := set.New[string]()
	for _, p := range providers.AllProviders() {
		m.Append(string(p))
	}
	m.Append("kind") // kubernetes
	return m
}

var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	ruleNamespaces           set.Set[string]
	policies                 map[string]*ast.Module
	store                    storage.Store
	runtimeValues            *ast.Term
	compiler                 *ast.Compiler
	regoErrorLimit           int
	logger                   *log.Logger
	traceWriter              io.Writer
	tracePerResult           bool
	retriever                *MetadataRetriever
	policyFS                 fs.FS
	policyDirs               []string
	policyReaders            []io.Reader
	dataFS                   fs.FS
	dataDirs                 []string
	frameworks               []framework.Framework
	inputSchema              any // unmarshalled into this from a json schema document
	sourceType               types.Source
	includeDeprecatedChecks  bool
	includeEmbeddedPolicies  bool
	includeEmbeddedLibraries bool

	embeddedLibs   map[string]*ast.Module
	embeddedChecks map[string]*ast.Module
	customSchemas  map[string][]byte

	disabledCheckIDs set.Set[string]
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

type DynamicMetadata struct {
	Warning   bool
	Filepath  string
	Message   string
	StartLine int
	EndLine   int
}

func NewScanner(source types.Source, opts ...options.ScannerOption) *Scanner {
	LoadAndRegister()

	schema, ok := schemas.SchemaMap[source]
	if !ok {
		schema = schemas.Anything
	}

	s := &Scanner{
		regoErrorLimit:   ast.CompileErrorLimitDefault,
		sourceType:       source,
		ruleNamespaces:   builtinNamespaces.Clone(),
		runtimeValues:    addRuntimeValues(),
		logger:           log.WithPrefix("rego"),
		customSchemas:    make(map[string][]byte),
		disabledCheckIDs: set.New[string](),
	}

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
	resultSet, err := instance.Eval(ctx)
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
	return resultSet, traces, nil
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

	s.logger.Debug("Scanning inputs", "count", len(inputs))

	var results scan.Results

	for _, module := range s.policies {

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		namespace := getModuleNamespace(module)
		topLevel := strings.Split(namespace, ".")[0]
		if !s.ruleNamespaces.Contains(topLevel) {
			continue
		}

		staticMeta, err := s.retriever.RetrieveMetadata(ctx, module, GetInputsContents(inputs)...)
		if err != nil {
			s.logger.Error(
				"Error occurred while retrieving metadata from check",
				log.FilePath(module.Package.Location.File),
				log.Err(err),
			)
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

		usedRules := set.New[string]()

		// all rules
		for _, rule := range module.Rules {
			ruleName := rule.Head.Name.String()
			if usedRules.Contains(ruleName) {
				continue
			}
			usedRules.Append(ruleName)
			if isEnforcedRule(ruleName) {
				ruleResults, err := s.applyRule(ctx, namespace, ruleName, inputs)
				if err != nil {
					s.logger.Error(
						"Error occurred while applying rule from check",
						log.String("rule", ruleName),
						log.FilePath(module.Package.Location.File),
						log.Err(err),
					)
					continue
				}
				results = append(results, s.embellishResultsWithRuleMetadata(ruleResults, *staticMeta)...)
			}
		}

	}

	return results, nil
}

func isPolicyWithSubtype(sourceType types.Source) bool {
	return checkTypesWithSubtype.Contains(sourceType)
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
				if !supportedProviders.Contains(provider) {
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

func (s *Scanner) applyRule(ctx context.Context, namespace, rule string, inputs []Input) (scan.Results, error) {
	var results scan.Results
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	for _, input := range inputs {
		s.trace("INPUT", input)
		parsedInput, err := parseRawInput(input.Contents)
		if err != nil {
			s.logger.Error("Error occurred while parsing input", log.Err(err))
			continue
		}

		resultSet, traces, err := s.runQuery(ctx, qualified, parsedInput, false)
		if err != nil {
			return nil, err
		}
		s.trace("RESULTSET", resultSet)
		ruleResults := s.convertResults(resultSet, input, namespace, rule, traces)
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

// severity is now set with metadata, so deny/warn/violation now behave the same way
func isEnforcedRule(name string) bool {
	switch {
	case name == "deny", strings.HasPrefix(name, "deny_"):
		return true
	}
	return false
}
