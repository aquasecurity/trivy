package rego

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

var builtinNamespaces = set.New("builtin", "defsec", "appshield")

func BuiltinNamespaces() []string {
	return builtinNamespaces.Items()
}

func IsBuiltinNamespace(namespace string) bool {
	return lo.ContainsBy(BuiltinNamespaces(), func(ns string) bool {
		return strings.HasPrefix(namespace, ns+".")
	})
}

func IsRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func IsDotFile(name string) bool {
	return strings.HasPrefix(name, ".")
}

func (s *Scanner) loadPoliciesFromReaders(readers []io.Reader) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for i, r := range readers {
		moduleName := fmt.Sprintf("reader_%d", i)
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		module, err := ast.ParseModuleWithOpts(moduleName, string(data), ast.ParserOptions{
			ProcessAnnotation: true,
		})
		if err != nil {
			return nil, err
		}
		modules[moduleName] = module
	}
	return modules, nil
}

func (s *Scanner) loadEmbedded() error {
	loaded, err := LoadEmbeddedLibraries()
	if err != nil {
		return fmt.Errorf("failed to load embedded rego libraries: %w", err)
	}
	s.embeddedLibs = loaded
	s.logger.Debug("Embedded libraries are loaded", log.Int("count", len(loaded)))

	loaded, err = LoadEmbeddedPolicies()
	if err != nil {
		return fmt.Errorf("failed to load embedded rego checks: %w", err)
	}
	s.embeddedChecks = loaded
	s.logger.Debug("Embedded checks are loaded", log.Int("count", len(loaded)))

	return nil
}

func (s *Scanner) LoadPolicies(srcFS fs.FS) error {

	modules := make(map[string]*ast.Module)

	if s.policyFS != nil {
		s.logger.Debug("Overriding filesystem for checks")
		srcFS = s.policyFS
	}

	if err := s.loadEmbedded(); err != nil {
		return err
	}

	if s.includeEmbeddedPolicies {
		modules = lo.Assign(modules, s.embeddedChecks)
	}

	if s.includeEmbeddedLibraries {
		modules = lo.Assign(modules, s.embeddedLibs)
	}

	var err error
	if len(s.policyDirs) > 0 {
		loaded, err := LoadPoliciesFromDirs(srcFS, s.policyDirs...)
		if err != nil {
			return fmt.Errorf("failed to load rego checks from %s: %w", s.policyDirs, err)
		}
		for name, policy := range loaded {
			modules[name] = policy
		}
		s.logger.Debug("Checks from disk are loaded", log.Int("count", len(loaded)))
	}

	if len(s.policyReaders) > 0 {
		loaded, err := s.loadPoliciesFromReaders(s.policyReaders)
		if err != nil {
			return fmt.Errorf("failed to load rego checks from reader(s): %w", err)
		}
		for name, policy := range loaded {
			modules[name] = policy
		}
		s.logger.Debug("Checks from readers are loaded", log.Int("count", len(loaded)))
	}

	// gather namespaces
	uniq := set.New[string]()
	for _, module := range modules {
		namespace := getModuleNamespace(module)
		uniq.Append(namespace)
	}
	namespaces := uniq.Items()

	dataFS := srcFS
	if s.dataFS != nil {
		s.logger.Debug("Overriding filesystem for data")
		dataFS = s.dataFS
	}
	store, err := initStore(dataFS, s.dataDirs, namespaces)
	if err != nil {
		return fmt.Errorf("unable to load data: %w", err)
	}

	compiler, filtered, err := s.compilePolicies(srcFS, s.policyDirs, modules)
	if err != nil {
		return fmt.Errorf("compile modules: %w", err)
	}

	s.runners = append(s.runners, &ChecksRunner{
		logger:         log.WithPrefix("check runner"),
		namespaces:     s.namespaces,
		modules:        filtered,
		runtimeValues:  initRuntimeValues(),
		store:          store,
		compiler:       compiler,
		retriever:      NewMetadataRetriever(compiler),
		traceWriter:    s.traceWriter,
		tracePerResult: s.tracePerResult,
	})
	return nil
}

func (s *Scanner) fallbackChecks(compiler *ast.Compiler, modules map[string]*ast.Module) {

	var excludedFiles []string

	for _, e := range compiler.Errors {
		if e.Location == nil {
			continue
		}

		loc := e.Location.File

		if lo.Contains(excludedFiles, loc) {
			continue
		}

		badPolicy, exists := modules[loc]
		if !exists || badPolicy == nil {
			continue
		}

		if !IsBuiltinNamespace(getModuleNamespace(badPolicy)) {
			continue
		}

		s.logger.Error(
			"Error occurred while parsing. Trying to fallback to embedded check",
			log.FilePath(loc),
			log.Err(e),
		)

		embedded := s.findMatchedEmbeddedCheck(badPolicy)
		if embedded == nil {
			s.logger.Error("Failed to find embedded check, skipping", log.FilePath(loc))
			continue
		}

		s.logger.Debug("Found embedded check", log.FilePath(embedded.Package.Location.File))
		delete(modules, loc) // remove bad check
		modules[embedded.Package.Location.File] = embedded
		delete(s.embeddedChecks, embedded.Package.Location.File) // avoid infinite loop if embedded check contains ref error
		excludedFiles = append(excludedFiles, e.Location.File)
	}

	compiler.Errors = lo.Filter(compiler.Errors, func(e *ast.Error, _ int) bool {
		return e.Location == nil || !lo.Contains(excludedFiles, e.Location.File)
	})
}

func (s *Scanner) findMatchedEmbeddedCheck(badPolicy *ast.Module) *ast.Module {
	for _, embeddedCheck := range s.embeddedChecks {
		if embeddedCheck.Package.Path.String() == badPolicy.Package.Path.String() {
			return embeddedCheck
		}
	}

	badPolicyMeta, err := metadataFromRegoModule(badPolicy)
	if err != nil {
		return nil
	}

	for _, embeddedCheck := range s.embeddedChecks {
		meta, err := metadataFromRegoModule(embeddedCheck)
		if err != nil {
			continue
		}
		if badPolicyMeta.AVDID != "" && badPolicyMeta.AVDID == meta.AVDID {
			return embeddedCheck
		}
	}
	return nil
}

func (s *Scanner) prunePoliciesWithError(compiler *ast.Compiler, modules map[string]*ast.Module) error {
	if len(compiler.Errors) > s.regoErrorLimit {
		s.logger.Error("Error(s) occurred while loading checks")
		return compiler.Errors
	}

	for _, e := range compiler.Errors {
		if e.Location == nil {
			continue
		}
		s.logger.Error(
			"Error occurred while parsing",
			log.FilePath(e.Location.File), log.Err(e),
		)
		delete(modules, e.Location.File)
	}
	return nil
}

func (s *Scanner) compilePolicies(
	srcFS fs.FS, paths []string, modules map[string]*ast.Module,
) (*ast.Compiler, map[string]*ast.Module, error) {

	schemaSet, err := BuildSchemaSetFromPolicies(modules, paths, srcFS, s.customSchemas)
	if err != nil {
		return nil, nil, fmt.Errorf("build schema set: %w", err)
	}

	compiler := ast.NewCompiler().
		WithUseTypeCheckAnnotations(true).
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithSchemas(schemaSet)

	compiler.Compile(modules)
	if compiler.Failed() {
		s.fallbackChecks(compiler, modules)
		if err := s.prunePoliciesWithError(compiler, modules); err != nil {
			return nil, nil, err
		}
		return s.compilePolicies(srcFS, paths, modules)
	}

	filtered, err := s.filterModules(compiler, modules)
	if err != nil {
		return nil, nil, fmt.Errorf("filter modules: %w", err)
	}

	return compiler, filtered, nil
}

func (s *Scanner) filterModules(compiler *ast.Compiler, modules map[string]*ast.Module) (map[string]*ast.Module, error) {
	retriever := NewMetadataRetriever(compiler)
	filtered := make(map[string]*ast.Module)
	for name, module := range modules {
		meta, err := retriever.RetrieveMetadata(context.TODO(), module)
		if err != nil {
			return nil, err
		}

		if !s.includeDeprecatedChecks && meta.Deprecated {
			continue
		}

		if !meta.hasAnyFramework(s.frameworks) {
			continue
		}

		if IsBuiltinNamespace(getModuleNamespace(module)) {
			if s.disabledCheckIDs.Contains(meta.ID) { // ignore builtin disabled checks
				continue
			}
		}

		if len(meta.InputOptions.Selectors) == 0 {
			if !meta.Library {
				s.logger.Warn(
					"Module has no input selectors - it will be loaded for all inputs!",
					log.FilePath(module.Package.Location.File),
					log.String("module", name),
				)
			}
		}

		filtered[name] = module
	}

	return filtered, nil
}
