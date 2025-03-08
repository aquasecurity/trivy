package rego

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"

	checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/log"
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
	maps.Copy(modules, loadedLibs)

	RegisterRegoRules(modules)
})

func RegisterRegoRules(modules map[string]*ast.Module) {
	ctx := context.TODO()

	schemaSet, _ := BuildSchemaSetFromPolicies(modules, nil, nil, make(map[string][]byte))

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

	for _, module := range modules {
		metadata, err := retriever.RetrieveMetadata(ctx, module)
		if err != nil {
			log.Warn("Failed to retrieve metadata",
				log.String("package", module.Package.String()), log.Err(err))
			continue
		} else if metadata == nil {
			continue
		}

		if metadata.AVDID == "" {
			if !metadata.Library {
				log.Warn("Check ID is empty", log.FilePath(module.Package.Location.File))
			}
			continue
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
	res, err := loader.NewFileLoader().
		WithFS(target).
		WithProcessAnnotation(true).
		Filtered(paths, func(abspath string, info fs.FileInfo, _ int) bool {
			return isNotRegoFile(info) || isOptionalChecks(abspath)
		})
	if err != nil {
		return nil, fmt.Errorf("load modules: %w", err)
	}
	return res.ParsedModules(), nil
}

func isNotRegoFile(fi fs.FileInfo) bool {
	return !fi.IsDir() && (!IsRegoFile(fi.Name()) || IsDotFile(fi.Name()))
}

func isOptionalChecks(path string) bool {
	return strings.HasSuffix(filepath.Dir(filepath.ToSlash(path)), filepath.Join("advanced", "optional"))
}
