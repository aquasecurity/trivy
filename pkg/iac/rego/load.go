package rego

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/version/doc"
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

func getModuleNamespace(module *ast.Module) string {
	return strings.TrimPrefix(module.Package.Path.String(), "data.")
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

	if s.policies == nil {
		s.policies = make(map[string]*ast.Module)
	}

	if s.policyFS != nil {
		s.logger.Debug("Overriding filesystem for checks")
		srcFS = s.policyFS
	}

	if err := s.loadEmbedded(); err != nil {
		return err
	}

	if s.includeEmbeddedPolicies {
		s.policies = lo.Assign(s.policies, s.embeddedChecks)
	}

	if s.includeEmbeddedLibraries {
		s.policies = lo.Assign(s.policies, s.embeddedLibs)
	}

	var err error
	if len(s.policyDirs) > 0 {
		loaded, err := LoadPoliciesFromDirs(srcFS, s.policyDirs...)
		if err != nil {
			return fmt.Errorf("failed to load rego checks from %s: %w", s.policyDirs, err)
		}
		maps.Copy(s.policies, loaded)
		s.logger.Debug("Checks from disk are loaded", log.Int("count", len(loaded)))
	}

	if len(s.policyReaders) > 0 {
		loaded, err := s.loadPoliciesFromReaders(s.policyReaders)
		if err != nil {
			return fmt.Errorf("failed to load rego checks from reader(s): %w", err)
		}
		maps.Copy(s.policies, loaded)
		s.logger.Debug("Checks from readers are loaded", log.Int("count", len(loaded)))
	}

	// gather namespaces
	uniq := set.New[string]()
	for _, module := range s.policies {
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
	s.store = store

	return s.compilePolicies(srcFS, s.policyDirs)
}

func (s *Scanner) fallbackChecks(compiler *ast.Compiler) {

	var excludedFiles []string

	for _, e := range compiler.Errors {
		if e.Location == nil {
			continue
		}

		loc := e.Location.File

		if lo.Contains(excludedFiles, loc) {
			continue
		}

		badPolicy, exists := s.policies[loc]
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
		delete(s.policies, loc) // remove bad check
		s.policies[embedded.Package.Location.File] = embedded
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

	badPolicyMeta, err := MetadataFromAnnotations(badPolicy)
	if err != nil {
		return nil
	}

	for _, embeddedCheck := range s.embeddedChecks {
		meta, err := MetadataFromAnnotations(embeddedCheck)
		if err != nil {
			continue
		}
		if badPolicyMeta.AVDID != "" && badPolicyMeta.AVDID == meta.AVDID {
			return embeddedCheck
		}
	}
	return nil
}

func (s *Scanner) prunePoliciesWithError(compiler *ast.Compiler) error {
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
		delete(s.policies, e.Location.File)
	}
	return nil
}

func (s *Scanner) compilePolicies(srcFS fs.FS, paths []string) error {
	for path, module := range s.policies {
		s.handleModulesMetadata(path, module)
	}

	schemaSet, err := BuildSchemaSetFromPolicies(s.policies, paths, srcFS, s.customSchemas)
	if err != nil {
		return err
	}

	compiler := ast.NewCompiler().
		WithUseTypeCheckAnnotations(true).
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithSchemas(schemaSet)

	compiler.Compile(s.policies)
	if compiler.Failed() {
		s.fallbackChecks(compiler)
		if err := s.prunePoliciesWithError(compiler); err != nil {
			return err
		}
		return s.compilePolicies(srcFS, paths)
	}

	s.retriever = NewMetadataRetriever(compiler)

	if err := s.filterModules(); err != nil {
		return fmt.Errorf("filter modules: %w", err)
	}
	s.compiler = compiler
	return nil
}

func (s *Scanner) handleModulesMetadata(path string, module *ast.Module) {
	if moduleHasLegacyInputFormat(module) {
		s.logger.Warn(
			"Module has legacy input format - please update to use annotations",
			log.FilePath(module.Package.Location.File),
			log.String("details", doc.URL("/docs/scanner/misconfiguration/custom", "input")),
		)
	}

	if moduleHasLegacyMetadataFormat(module) {
		s.logger.Warn(
			"Module has legacy metadata format - please update to use annotations",
			log.FilePath(module.Package.Location.File),
			log.String("details", doc.URL("/docs/scanner/misconfiguration/custom", "metadata")),
		)
		return
	}

	metadata, err := MetadataFromAnnotations(module)
	if err != nil {
		s.logger.Error(
			"Failed to retrieve metadata from annotations",
			log.FilePath(module.Package.Location.File),
			log.Err(err),
		)
		return
	}

	if metadata != nil {
		s.moduleMetadata[path] = metadata
	}
}

// moduleHasLegacyMetadataFormat checks if the module has a legacy metadata format.
// Returns true if the metadata is represented as a “__rego_metadata__” rule,
// which was used before annotations were introduced.
func moduleHasLegacyMetadataFormat(module *ast.Module) bool {
	return slices.ContainsFunc(module.Rules, func(rule *ast.Rule) bool {
		return rule.Head.Name.Equal(ast.Var("__rego_metadata__"))
	})
}

// moduleHasLegacyInputFormat checks if the module has a legacy input format.
// Returns true if the input is represented as a “__rego_input__” rule,
// which was used before annotations were introduced.
func moduleHasLegacyInputFormat(module *ast.Module) bool {
	return slices.ContainsFunc(module.Rules, func(rule *ast.Rule) bool {
		return rule.Head.Name.Equal(ast.Var("__rego_input__"))
	})
}

// filterModules filters the Rego modules based on metadata.
func (s *Scanner) filterModules() error {
	filtered := make(map[string]*ast.Module)
	for name, module := range s.policies {
		metadata, err := s.metadataForModule(context.Background(), name, module, nil)
		if err != nil {
			return fmt.Errorf("retrieve metadata for module %s: %w", name, err)
		}

		if s.isModuleApplicable(module, metadata, name) {
			filtered[name] = module
		}
	}

	s.policies = filtered
	return nil
}

func (s *Scanner) isModuleApplicable(module *ast.Module, metadata *StaticMetadata, name string) bool {
	if !metadata.hasAnyFramework(s.frameworks) {
		return false
	}

	// ignore disabled built-in checks
	if IsBuiltinNamespace(getModuleNamespace(module)) && s.disabledCheckIDs.Contains(metadata.ID) {
		return false
	}

	if len(metadata.InputOptions.Selectors) == 0 && !metadata.Library {
		s.logger.Warn(
			"Module has no input selectors - it will be loaded for all inputs",
			log.FilePath(module.Package.Location.File),
			log.String("module", name),
		)
	}

	return true
}
