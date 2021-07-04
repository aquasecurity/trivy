package policy

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

var (
	warningRegex = regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$")
	failureRegex = regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$")
)

// Engine represents the policy engine.
type Engine struct {
	modules  map[string]*ast.Module
	compiler *ast.Compiler
	store    storage.Store
	policies map[string]string
	docs     map[string]string
}

// Load returns an Engine after loading all of the specified policies and data paths.
func Load(policyPaths []string, dataPaths []string) (*Engine, error) {
	policies, err := loader.AllRegos(policyPaths)
	if err != nil {
		return nil, xerrors.Errorf("load: %w", err)
	} else if len(policies.Modules) == 0 {
		return nil, xerrors.Errorf("no policies found in %v", policyPaths)
	}

	compiler, err := policies.Compiler()
	if err != nil {
		return nil, xerrors.Errorf("get compiler: %w", err)
	}

	policyContents := make(map[string]string)
	for path, module := range policies.ParsedModules() {
		path = filepath.Clean(path)
		path = filepath.ToSlash(path)

		policyContents[path] = module.String()
	}

	modules := policies.ParsedModules()

	store, docs, err := loadData(dataPaths, allNamespaces(modules))
	if err != nil {
		return nil, xerrors.Errorf("unable to load data: %w", err)
	}

	return &Engine{
		modules:  modules,
		compiler: compiler,
		policies: policyContents,
		store:    store,
		docs:     docs,
	}, nil
}

func allNamespaces(modules map[string]*ast.Module) []string {
	uniq := map[string]struct{}{}
	for _, module := range modules {
		namespace := strings.Replace(module.Package.Path.String(), "data.", "", 1)
		uniq[namespace] = struct{}{}
	}

	var namespaces []string
	for ns := range uniq {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

func loadData(dataPaths, namespaces []string) (storage.Store, map[string]string, error) {
	// FilteredPaths will recursively find all file paths that contain a valid document
	// extension from the given list of data paths.
	allDocumentPaths, err := loader.FilteredPaths(dataPaths, func(abspath string, info os.FileInfo, depth int) bool {
		if info.IsDir() {
			return false
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		return !utils.StringInSlice(ext, []string{".yaml", ".yml", ".json"})
	})
	if err != nil {
		return nil, nil, xerrors.Errorf("filter data paths: %w", err)
	}

	documents, err := loader.NewFileLoader().All(allDocumentPaths)
	if err != nil {
		return nil, nil, xerrors.Errorf("load documents: %w", err)
	}

	// Pass all namespaces so that Rego rule can refer to namespaces as data.namespaces
	documents.Documents["namespaces"] = namespaces

	store, err := documents.Store()
	if err != nil {
		return nil, nil, xerrors.Errorf("get documents store: %w", err)
	}

	documentContents := make(map[string]string)
	for _, documentPath := range allDocumentPaths {
		contents, err := ioutil.ReadFile(documentPath)
		if err != nil {
			return nil, nil, xerrors.Errorf("read file: %w", err)
		}

		documentPath = filepath.Clean(documentPath)
		documentPath = filepath.ToSlash(documentPath)
		documentContents[documentPath] = string(contents)
	}

	return store, documentContents, nil
}

// Compiler returns the compiler from the loaded policies.
func (e *Engine) Compiler() *ast.Compiler {
	return e.compiler
}

// Store returns the store from the loaded documents.
func (e *Engine) Store() storage.Store {
	return e.store
}

// Modules returns the modules from the loaded policies.
func (e *Engine) Modules() map[string]*ast.Module {
	return e.modules
}

// Runtime returns the runtime of the engine.
func (e *Engine) Runtime() *ast.Term {
	env := ast.NewObject()
	for _, pair := range os.Environ() {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 1 {
			env.Insert(ast.StringTerm(parts[0]), ast.NullTerm())
		} else if len(parts) > 1 {
			env.Insert(ast.StringTerm(parts[0]), ast.StringTerm(parts[1]))
		}
	}

	obj := ast.NewObject()
	obj.Insert(ast.StringTerm("env"), ast.NewTerm(env))
	obj.Insert(ast.StringTerm("version"), ast.StringTerm(version.Version))
	obj.Insert(ast.StringTerm("commit"), ast.StringTerm(version.Vcs))

	return ast.NewTerm(obj)
}

// Check executes all of the loaded policies against the input and returns the results.
func (e *Engine) Check(ctx context.Context, configs []types.Config, namespaces []string) ([]types.Misconfiguration, error) {
	// e.g. kubernetes => {Type: "kubernetes",  FilePath: "deployment.yaml", Content: ...}
	typedConfigs := map[string][]types.Config{}
	for _, c := range configs {
		typedConfigs[c.Type] = append(typedConfigs[c.Type], c)
	}

	uniqMisconfs := map[string]types.Misconfiguration{}
	for _, module := range e.Modules() {
		currentNamespace := strings.Replace(module.Package.Path.String(), "data.", "", 1)
		if !underNamespaces(currentNamespace, namespaces) {
			continue
		}

		metadata, err := e.queryMetadata(ctx, currentNamespace)
		if err != nil {
			return nil, xerrors.Errorf("failed to query metadata: %w", err)
		}

		inputOption, err := e.queryInputOption(ctx, currentNamespace)
		if err != nil {
			return nil, xerrors.Errorf("failed to query input option: %w", err)
		}

		var selectedConfigs []types.Config
		if len(inputOption.Selectors) > 0 {
			// Pass only the config files that match the selector types
			for _, t := range uniqueSelectorTypes(inputOption.Selectors) {
				selectedConfigs = append(selectedConfigs, typedConfigs[t]...)
			}
		} else {
			// When the 'selector' is not specified, it means '*'.
			selectedConfigs = configs
		}

		// Extract deny and warn rules
		rules := entrypoints(module)

		var result map[string]types.Misconfiguration
		if inputOption.Combine {
			result, err = e.checkCombined(ctx, currentNamespace, rules, selectedConfigs, metadata)
		} else {
			result, err = e.check(ctx, currentNamespace, rules, selectedConfigs, metadata)
		}
		if err != nil {
			return nil, xerrors.Errorf("policy check error: %w", err)
		}

		for filePath, misconf := range result {
			uniqMisconfs[filePath] = mergeMisconfs(misconf, uniqMisconfs[filePath])
		}
	}

	return types.ToMisconfigurations(uniqMisconfs), nil
}

func (e Engine) check(ctx context.Context, currentNamespace string, rules []string, configs []types.Config,
	metadata types.PolicyMetadata) (map[string]types.Misconfiguration, error) {

	// Initialize misconfigurations
	misconfs := map[string]types.Misconfiguration{}
	for _, c := range configs {
		misconfs[c.FilePath] = types.Misconfiguration{
			FileType: c.Type,
			FilePath: c.FilePath,
		}
	}

	for _, config := range configs {
		for _, rule := range rules {
			result, err := e.checkRule(ctx, currentNamespace, rule, config.Content, metadata)
			if err != nil {
				return nil, xerrors.Errorf("check rule: %w", err)
			}
			misconfs[config.FilePath] = mergeMisconfs(misconfs[config.FilePath], result)
		}
	}

	return misconfs, nil
}

type combinedInput struct {
	Path     string      `json:"path"`
	Contents interface{} `json:"contents"`
}

func (e Engine) checkCombined(ctx context.Context, currentNamespace string, rules []string, configs []types.Config,
	metadata types.PolicyMetadata) (map[string]types.Misconfiguration, error) {
	var inputs []combinedInput
	misconfs := map[string]types.Misconfiguration{}
	for _, c := range configs {
		inputs = append(inputs, combinedInput{
			Path:     c.FilePath,
			Contents: c.Content,
		})
		misconfs[c.FilePath] = types.Misconfiguration{
			FileType: c.Type,
			FilePath: c.FilePath,
		}
	}

	for _, rule := range rules {
		results, err := e.checkRuleCombined(ctx, currentNamespace, rule, inputs, metadata)
		if err != nil {
			return nil, err
		}

		for filePath, res := range results {
			misconfs[filePath] = mergeMisconfs(misconfs[filePath], res)
		}
	}

	return misconfs, nil
}

func (e *Engine) checkRule(ctx context.Context, namespace, rule string, input interface{}, metadata types.PolicyMetadata) (
	types.Misconfiguration, error) {
	// Exceptions based on namespace and rule
	exceptions, err := e.exceptions(ctx, namespace, rule, input, metadata)
	if err != nil {
		return types.Misconfiguration{}, xerrors.Errorf("exception error: %w", err)
	} else if len(exceptions) > 0 {
		return types.Misconfiguration{
			Exceptions: exceptions,
		}, nil
	}

	ruleQuery := fmt.Sprintf("data.%s.%s", namespace, rule)
	ruleQueryResult, err := e.query(ctx, input, ruleQuery)
	if err != nil {
		return types.Misconfiguration{}, xerrors.Errorf("query rule: %w", err)
	}

	var successes, failures, warnings []types.MisconfResult
	for _, ruleResult := range ruleQueryResult.results {
		result := types.MisconfResult{
			Namespace:      namespace,
			Message:        ruleResult.Message,
			PolicyMetadata: metadata,
		}

		if ruleResult.Message == "" {
			continue
		} else if isFailure(rule) {
			failures = append(failures, result)
		} else {
			warnings = append(warnings, result)
		}
	}

	if len(failures) == 0 && len(warnings) == 0 {
		successes = append(successes, types.MisconfResult{
			Namespace:      namespace,
			PolicyMetadata: metadata,
		})
	}

	return types.Misconfiguration{
		Successes: successes,
		Failures:  failures,
		Warnings:  warnings,
	}, nil
}

func (e *Engine) checkRuleCombined(ctx context.Context, namespace, rule string, inputs []combinedInput, metadata types.PolicyMetadata) (
	map[string]types.Misconfiguration, error) {
	misconfs := map[string]types.Misconfiguration{}

	// Exceptions based on namespace and rule
	exceptions, err := e.exceptions(ctx, namespace, rule, inputs, metadata)
	if err != nil {
		return nil, xerrors.Errorf("exception error: %w", err)
	} else if len(exceptions) > 0 {
		for _, input := range inputs {
			misconfs[input.Path] = types.Misconfiguration{
				FilePath:   input.Path,
				Exceptions: exceptions,
			}
		}
		return misconfs, nil
	}

	ruleQuery := fmt.Sprintf("data.%s.%s", namespace, rule)
	ruleQueryResult, err := e.query(ctx, inputs, ruleQuery)
	if err != nil {
		return nil, xerrors.Errorf("query rule: %w", err)
	}

	// Fill failures and warnings
	for _, ruleResult := range ruleQueryResult.results {
		switch {
		case ruleResult.Message == "":
			continue
		case ruleResult.FilePath == "":
			return nil, xerrors.Errorf("rule missing 'filepath' field")
		}

		misconf := misconfs[ruleResult.FilePath]
		result := types.MisconfResult{
			Namespace:      namespace,
			Message:        ruleResult.Message,
			PolicyMetadata: metadata,
		}

		if isFailure(rule) {
			misconf.Failures = append(misconf.Failures, result)
		} else {
			misconf.Warnings = append(misconf.Warnings, result)
		}
		misconfs[ruleResult.FilePath] = misconf
	}

	// Fill successes
	success := types.MisconfResult{
		Namespace:      namespace,
		PolicyMetadata: metadata,
	}
	for _, input := range inputs {
		misconf, ok := misconfs[input.Path]
		if ok {
			continue
		}
		misconf.Successes = append(misconf.Successes, success)
		misconfs[input.Path] = misconf
	}

	return misconfs, nil
}

func (e *Engine) exceptions(ctx context.Context, namespace, rule string, config interface{},
	metadata types.PolicyMetadata) ([]types.MisconfResult, error) {
	exceptions, err := e.namespaceExceptions(ctx, namespace, config, metadata)
	if err != nil {
		return nil, xerrors.Errorf("namespace exceptions: %w", err)
	} else if len(exceptions) > 0 {
		return exceptions, nil
	}

	exceptions, err = e.ruleExceptions(ctx, namespace, rule, config, metadata)
	if err != nil {
		return nil, xerrors.Errorf("rule exceptions: %w", err)
	} else if len(exceptions) > 0 {
		return exceptions, nil
	}

	return nil, nil
}

func (e *Engine) namespaceExceptions(ctx context.Context, namespace string, config interface{},
	metadata types.PolicyMetadata) ([]types.MisconfResult, error) {
	exceptionQuery := fmt.Sprintf("data.namespace.exceptions.exception[_] == %q", namespace)
	exceptionQueryResult, err := e.query(ctx, config, exceptionQuery)
	if err != nil {
		return nil, xerrors.Errorf("query namespace exceptions: %w", err)
	}

	var exceptions []types.MisconfResult
	for _, exceptionResult := range exceptionQueryResult.results {
		// When an exception is found, set the message of the exception
		// to the query that triggered the exception so that it is known
		// which exception was triggered.
		if exceptionResult.Message == "" {
			exceptions = append(exceptions, types.MisconfResult{
				Namespace:      namespace,
				Message:        exceptionQuery,
				PolicyMetadata: metadata,
			})
		}
	}
	return exceptions, nil
}

func (e *Engine) ruleExceptions(ctx context.Context, namespace, rule string, config interface{},
	metadata types.PolicyMetadata) ([]types.MisconfResult, error) {
	exceptionQuery := fmt.Sprintf("data.%s.exception[_][_] == %q", namespace, removeRulePrefix(rule))
	exceptionQueryResult, err := e.query(ctx, config, exceptionQuery)
	if err != nil {
		return nil, xerrors.Errorf("query rule exceptions: %w", err)
	}

	var exceptions []types.MisconfResult
	for _, exceptionResult := range exceptionQueryResult.results {
		// When an exception is found, set the message of the exception
		// to the query that triggered the exception so that it is known
		// which exception was triggered.
		if exceptionResult.Message == "" {
			exceptions = append(exceptions, types.MisconfResult{
				Namespace:      namespace,
				Message:        exceptionQuery,
				PolicyMetadata: metadata,
			})
		}
	}
	return exceptions, nil
}

// queryResult describes the result of evaluating a query.
type queryResult struct {

	// Query is the fully qualified query that was used
	// to determine the result. Ex: (data.main.deny)
	query string

	// Results are the individual results of the query.
	// When querying data.main.deny, multiple deny rules can
	// exist, producing multiple results.
	results []queryValue

	// Traces represents a single trace of how the query was
	// evaluated. Each trace value is a trace line.
	traces []string
}

type queryValue struct {
	FilePath string
	Message  string
}

// query is a low-level method that has no notion of a failed policy or successful policy. // It only returns the result of executing a single query against the input.
//
// Example queries could include:
// data.main.deny to query the deny rule in the main namespace
// data.main.warn to query the warn rule in the main namespace
func (e *Engine) query(ctx context.Context, input interface{}, query string) (queryResult, error) {
	stdout := topdown.NewBufferTracer()
	options := []func(r *rego.Rego){
		rego.Input(input),
		rego.Query(query),
		rego.Compiler(e.Compiler()),
		rego.Store(e.Store()),
		rego.Runtime(e.Runtime()),
		rego.QueryTracer(stdout),
	}
	resultSet, err := rego.New(options...).Eval(ctx)
	if err != nil {
		return queryResult{}, xerrors.Errorf("evaluating policy: %w", err)
	}

	// After the evaluation of the policy, the results of the trace (stdout) will be populated
	// for the query. Once populated, format the trace results into a human readable format.
	buf := new(bytes.Buffer)
	topdown.PrettyTrace(buf, *stdout)
	var traces []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if len(line) > 0 {
			traces = append(traces, line)
		}
	}

	var results []queryValue
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			// Rego rules that are intended for evaluation should return a slice of values.
			// For example, deny[msg] or violation[{"msg": msg}].
			//
			// When an expression does not have a slice of values, the expression did not
			// evaluate to true, and no message was returned.
			var expressionValues []interface{}
			if _, ok := expression.Value.([]interface{}); ok {
				expressionValues = expression.Value.([]interface{})
			}
			if len(expressionValues) == 0 {
				results = append(results, queryValue{})
				continue
			}

			for _, v := range expressionValues {
				switch val := v.(type) {
				case string:
					// Policies that only return a single string (e.g. deny[msg])
					results = append(results, queryValue{Message: val})
				case map[string]interface{}:
					msg, filePath, err := parseResult(val)
					if err != nil {
						return queryResult{}, xerrors.Errorf("failed to parse query result: %w", err)
					}

					results = append(results, queryValue{
						Message:  strings.TrimSpace(msg),
						FilePath: filePath,
					})
				}
			}
		}
	}

	return queryResult{
		query:   query,
		results: results,
		traces:  traces,
	}, nil
}

func (e *Engine) queryMetadata(ctx context.Context, namespace string) (types.PolicyMetadata, error) {
	query := fmt.Sprintf("x = data.%s.__rego_metadata__", namespace)
	options := []func(r *rego.Rego){
		rego.Query(query),
		rego.Compiler(e.Compiler()),
		rego.Store(e.Store()),
	}
	resultSet, err := rego.New(options...).Eval(ctx)
	if err != nil {
		return types.PolicyMetadata{}, xerrors.Errorf("evaluating '__rego_metadata__': %w", err)
	}

	// Set default values
	metadata := types.PolicyMetadata{
		ID:       "N/A",
		Type:     "N/A",
		Title:    "N/A",
		Severity: "UNKNOWN",
	}

	if len(resultSet) == 0 {
		return metadata, nil
	}

	result, ok := resultSet[0].Bindings["x"].(map[string]interface{})
	if !ok {
		return types.PolicyMetadata{}, xerrors.New("'__rego_metadata__' must be map")
	}

	if err = mapstructure.Decode(result, &metadata); err != nil {
		return types.PolicyMetadata{}, xerrors.Errorf("decode error: %w", err)
	}

	// e.g. Low -> LOW
	metadata.Severity = strings.ToUpper(metadata.Severity)

	return metadata, nil
}

func (e *Engine) queryInputOption(ctx context.Context, namespace string) (types.PolicyInputOption, error) {
	query := fmt.Sprintf("x = data.%s.__rego_input__", namespace)
	options := []func(r *rego.Rego){
		rego.Query(query),
		rego.Compiler(e.Compiler()),
		rego.Store(e.Store()),
	}
	resultSet, err := rego.New(options...).Eval(ctx)
	if err != nil {
		return types.PolicyInputOption{}, xerrors.Errorf("evaluating '__rego_input__': %w", err)
	}

	if len(resultSet) == 0 {
		return types.PolicyInputOption{}, nil
	}

	result, ok := resultSet[0].Bindings["x"].(map[string]interface{})
	if !ok {
		return types.PolicyInputOption{}, xerrors.New("'__rego_input__' must be map")
	}

	var inputOption types.PolicyInputOption
	if err = mapstructure.Decode(result, &inputOption); err != nil {
		return types.PolicyInputOption{}, xerrors.Errorf("decode error: %w", err)
	}

	return inputOption, nil
}

func entrypoints(module *ast.Module) []string {
	uniqRules := map[string]struct{}{}
	for r := range module.Rules {
		currentRule := module.Rules[r].Head.Name.String()
		if isFailure(currentRule) || isWarning(currentRule) {
			uniqRules[currentRule] = struct{}{}
		}
	}
	return utils.Keys(uniqRules)
}

func parseResult(r map[string]interface{}) (string, string, error) {
	// Policies that return metadata (e.g. deny[{"msg": msg}])
	if _, ok := r["msg"]; !ok {
		return "", "", xerrors.Errorf("rule missing 'msg' field: %v", r)
	}

	msg, ok := r["msg"].(string)
	if !ok {
		return "", "", xerrors.Errorf("'msg' field must be string: %v", r)
	}

	filePath, ok := r["filepath"].(string)
	if !ok {
		return msg, "", nil
	}

	return msg, filePath, nil
}

func isWarning(rule string) bool {
	return warningRegex.MatchString(rule)
}

func isFailure(rule string) bool {
	return failureRegex.MatchString(rule)
}

// When matching rules for exceptions, only the name of the rule
// is queried, so the severity prefix must be removed.
func removeRulePrefix(rule string) string {
	rule = strings.TrimPrefix(rule, "violation_")
	rule = strings.TrimPrefix(rule, "deny_")
	rule = strings.TrimPrefix(rule, "warn_")

	return rule
}

func uniqueSelectorTypes(selectors []types.PolicyInputSelector) []string {
	selectorTypes := map[string]struct{}{}
	for _, s := range selectors {
		selectorTypes[s.Type] = struct{}{}
	}
	return utils.Keys(selectorTypes)
}

func underNamespaces(current string, namespaces []string) bool {
	// e.g.
	//  current: 'main',     namespaces: []string{'main'}     => true
	//  current: 'main.foo', namespaces: []string{'main'}     => true
	//  current: 'main.foo', namespaces: []string{'main.bar'} => false
	for _, ns := range namespaces {
		if current == ns || strings.HasPrefix(current, ns+".") {
			return true
		}
	}
	return false
}

func mergeMisconfs(a, b types.Misconfiguration) types.Misconfiguration {
	a.Successes = append(a.Successes, b.Successes...)
	a.Warnings = append(a.Warnings, b.Warnings...)
	a.Failures = append(a.Failures, b.Failures...)
	a.Exceptions = append(a.Exceptions, b.Exceptions...)
	return a
}
