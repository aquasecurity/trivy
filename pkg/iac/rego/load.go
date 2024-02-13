package rego

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
)

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

func (s *Scanner) loadEmbedded(enableEmbeddedLibraries, enableEmbeddedPolicies bool) error {
	if enableEmbeddedLibraries {
		loadedLibs, errLoad := LoadEmbeddedLibraries()
		if errLoad != nil {
			return fmt.Errorf("failed to load embedded rego libraries: %w", errLoad)
		}
		for name, policy := range loadedLibs {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d embedded libraries.", len(loadedLibs))
	}

	if enableEmbeddedPolicies {
		loaded, err := LoadEmbeddedPolicies()
		if err != nil {
			return fmt.Errorf("failed to load embedded rego policies: %w", err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d embedded policies.", len(loaded))
	}

	return nil
}

func (s *Scanner) LoadPolicies(enableEmbeddedLibraries, enableEmbeddedPolicies bool, srcFS fs.FS, paths []string, readers []io.Reader) error {

	if s.policies == nil {
		s.policies = make(map[string]*ast.Module)
	}

	if s.policyFS != nil {
		s.debug.Log("Overriding filesystem for policies!")
		srcFS = s.policyFS
	}

	if err := s.loadEmbedded(enableEmbeddedLibraries, enableEmbeddedPolicies); err != nil {
		return err
	}

	var err error
	if len(paths) > 0 {
		loaded, err := LoadPoliciesFromDirs(srcFS, paths...)
		if err != nil {
			return fmt.Errorf("failed to load rego policies from %s: %w", paths, err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d policies from disk.", len(loaded))
	}

	if len(readers) > 0 {
		loaded, err := s.loadPoliciesFromReaders(readers)
		if err != nil {
			return fmt.Errorf("failed to load rego policies from reader(s): %w", err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d policies from reader(s).", len(loaded))
	}

	// gather namespaces
	uniq := make(map[string]struct{})
	for _, module := range s.policies {
		namespace := getModuleNamespace(module)
		uniq[namespace] = struct{}{}
	}
	var namespaces []string
	for namespace := range uniq {
		namespaces = append(namespaces, namespace)
	}

	dataFS := srcFS
	if s.dataFS != nil {
		s.debug.Log("Overriding filesystem for data!")
		dataFS = s.dataFS
	}
	store, err := initStore(dataFS, s.dataDirs, namespaces)
	if err != nil {
		return fmt.Errorf("unable to load data: %w", err)
	}
	s.store = store

	return s.compilePolicies(srcFS, paths)
}

func (s *Scanner) prunePoliciesWithError(compiler *ast.Compiler) error {
	if len(compiler.Errors) > s.regoErrorLimit {
		s.debug.Log("Error(s) occurred while loading policies")
		return compiler.Errors
	}

	for _, e := range compiler.Errors {
		s.debug.Log("Error occurred while parsing: %s, %s", e.Location.File, e.Error())
		delete(s.policies, e.Location.File)
	}
	return nil
}

func (s *Scanner) compilePolicies(srcFS fs.FS, paths []string) error {

	schemaSet, custom, err := BuildSchemaSetFromPolicies(s.policies, paths, srcFS)
	if err != nil {
		return err
	}
	if custom {
		s.inputSchema = nil // discard auto detected input schema in favor of policy defined schema
	}

	compiler := ast.NewCompiler().
		WithUseTypeCheckAnnotations(true).
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithSchemas(schemaSet)

	compiler.Compile(s.policies)
	if compiler.Failed() {
		if err := s.prunePoliciesWithError(compiler); err != nil {
			return err
		}
		return s.compilePolicies(srcFS, paths)
	}
	retriever := NewMetadataRetriever(compiler)

	if err := s.filterModules(retriever); err != nil {
		return err
	}
	if s.inputSchema != nil {
		schemaSet := ast.NewSchemaSet()
		schemaSet.Put(ast.MustParseRef("schema.input"), s.inputSchema)
		compiler.WithSchemas(schemaSet)
		compiler.Compile(s.policies)
		if compiler.Failed() {
			if err := s.prunePoliciesWithError(compiler); err != nil {
				return err
			}
			return s.compilePolicies(srcFS, paths)
		}
	}
	s.compiler = compiler
	s.retriever = retriever
	return nil
}

func (s *Scanner) filterModules(retriever *MetadataRetriever) error {

	filtered := make(map[string]*ast.Module)
	for name, module := range s.policies {
		meta, err := retriever.RetrieveMetadata(context.TODO(), module)
		if err != nil {
			return err
		}
		if len(meta.InputOptions.Selectors) == 0 {
			s.debug.Log("WARNING: Module %s has no input selectors - it will be loaded for all inputs!", name)
			filtered[name] = module
			continue
		}
		for _, selector := range meta.InputOptions.Selectors {
			if selector.Type == string(s.sourceType) {
				filtered[name] = module
				break
			}
		}
	}

	s.policies = filtered
	return nil
}
