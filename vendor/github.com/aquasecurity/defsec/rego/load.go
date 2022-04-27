package rego

import (
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/bundle"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
)

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func (s *Scanner) loadPoliciesFromDirs(paths []string) (map[string]*ast.Module, error) {
	// load policies matching *.rego except for *_test.rego
	loaded, err := loader.NewFileLoader().Filtered(paths, func(_ string, info os.FileInfo, depth int) bool {
		return !info.IsDir() && !isRegoFile(info.Name())
	})
	if err != nil {
		return nil, err
	}
	return loaded.ParsedModules(), nil
}

func (s *Scanner) LoadPolicies(loadEmbedded bool, paths ...string) error {

	if s.policies == nil {
		s.policies = make(map[string]*ast.Module)
	}

	if loadEmbedded {
		loaded, err := loadEmbeddedPolicies()
		if err != nil {
			return fmt.Errorf("failed to load embedded rego policies: %w", err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
	}

	var err error
	if len(paths) > 0 {
		loaded, err := s.loadPoliciesFromDirs(paths)
		if err != nil {
			return fmt.Errorf("failed to load rego policies from %s: %w", paths, err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
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
	store, err := initStore(s.dataDirs, namespaces)
	if err != nil {
		return fmt.Errorf("unable to load data: %w", err)
	}
	s.store = store

	compiler := ast.NewCompiler()
	compiler.Compile(s.policies)
	if compiler.Failed() {
		return compiler.Errors
	}
	s.compiler = compiler

	s.retriever = NewMetadataRetriever(compiler)

	return nil
}
