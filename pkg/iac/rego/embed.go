package rego

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/ast"

	checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

var LoadAndRegister = sync.OnceFunc(func() {
	modules, err := LoadEmbeddedPolicies()
	if err != nil {
		// we should panic as the policies were not embedded properly
		panic(err)
	}
	loadedLibs, err := LoadEmbeddedLibraries()
	if err != nil {
		panic(err)
	}
	for name, policy := range loadedLibs {
		modules[name] = policy
	}

	RegisterRegoRules(modules)
})

func RegisterRegoRules(modules map[string]*ast.Module) {
	ctx := context.TODO()

	schemaSet, _, _ := BuildSchemaSetFromPolicies(modules, nil, nil, make(map[string][]byte))

	compiler := ast.NewCompiler().
		WithSchemas(schemaSet).
		WithCapabilities(nil).
		WithUseTypeCheckAnnotations(true)

	compiler.Compile(modules)
	if compiler.Failed() {
		// we should panic as the embedded rego policies are syntactically incorrect...
		panic(compiler.Errors)
	}

	retriever := NewMetadataRetriever(compiler)
	regoCheckIDs := set.New[string]()

	for _, module := range modules {
		metadata, err := retriever.RetrieveMetadata(ctx, module)
		if err != nil {
			log.Warn("Failed to retrieve metadata", log.String("package", module.Package.String()), log.Err(err))
			continue
		}

		if metadata.AVDID == "" {
			if !metadata.Library {
				log.Warn("Check ID is empty", log.FilePath(module.Package.Location.File))
			}
			continue
		}

		if !metadata.Deprecated {
			regoCheckIDs.Append(metadata.AVDID)
		}

		rules.Register(metadata.ToRule())
	}
}

func LoadEmbeddedPolicies() (map[string]*ast.Module, error) {
	return LoadPoliciesFromDirs(checks.EmbeddedPolicyFileSystem, ".")
}

func LoadEmbeddedLibraries() (map[string]*ast.Module, error) {
	return LoadPoliciesFromDirs(checks.EmbeddedLibraryFileSystem, ".")
}

func LoadPoliciesFromDirs(target fs.FS, paths ...string) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for _, path := range paths {
		if err := fs.WalkDir(target, sanitisePath(path), func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			if strings.HasSuffix(filepath.Dir(filepath.ToSlash(path)), filepath.Join("advanced", "optional")) {
				return fs.SkipDir
			}

			if !IsRegoFile(info.Name()) || IsDotFile(info.Name()) {
				return nil
			}
			data, err := fs.ReadFile(target, filepath.ToSlash(path))
			if err != nil {
				return err
			}
			module, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{
				ProcessAnnotation: true,
			})
			if err != nil {
				return fmt.Errorf("failed to parse Rego module: %w", err)
			}
			modules[path] = module
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return modules, nil
}
