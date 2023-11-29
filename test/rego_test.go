package test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trivyRego "github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/rego/schemas"
	"github.com/aquasecurity/trivy-policies/rules"
)

var embeddedFilesystems = []fs.FS{rules.EmbeddedLibraryFileSystem, rules.EmbeddedPolicyFileSystem}

type walkDirFunc func(fs.FS) fs.WalkDirFunc

func walkOverFilesystems(root string, fn walkDirFunc, filesystems ...fs.FS) error {
	for _, fsys := range filesystems {
		if err := fs.WalkDir(fsys, root, fn(fsys)); err != nil {
			return err
		}
	}
	return nil
}

func Test_AllRegoCloudRulesMatchSchema(t *testing.T) {

	// load all the tests first
	baseModules := make(map[string]*ast.Module)
	walkDirFunc := func(fsys fs.FS) fs.WalkDirFunc {
		return func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(path) != ".rego" {
				return nil
			}

			data, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			module, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{
				ProcessAnnotation: true,
			})
			if err != nil {
				return err
			}

			if strings.HasSuffix(path, "_test.rego") {
				return nil
			}

			baseModules[path] = module
			return nil
		}
	}

	require.NoError(t, walkOverFilesystems("cloud", walkDirFunc, rules.EmbeddedPolicyFileSystem))

	var schema interface{}
	require.NoError(t, json.Unmarshal([]byte(schemas.Cloud), &schema))

	schemaSet := ast.NewSchemaSet()
	schemaSet.Put(ast.MustParseRef("schema.cloud"), schema)

	compiler := ast.NewCompiler().
		WithUseTypeCheckAnnotations(true).
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithSchemas(schemaSet)

	compiler.Compile(baseModules)
	assert.False(t, compiler.Failed(), "compilation failed: %s", compiler.Errors)
}

func Test_AllRegoRules(t *testing.T) {

	// load all the tests first
	baseModules := make(map[string]*ast.Module)
	testModules := make(map[string]*ast.Module)
	walkDirFunc := func(fsys fs.FS) fs.WalkDirFunc {
		return func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(path) != ".rego" {
				return nil
			}

			data, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			module, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{
				ProcessAnnotation: true,
			})
			if err != nil {
				return err
			}

			baseModules[path] = module

			// this is a library file or a rule file
			if !strings.HasSuffix(path, "_test.rego") {
				return nil
			}

			testModules[path] = module
			return nil
		}
	}
	require.NoError(t, walkOverFilesystems(".", walkDirFunc, embeddedFilesystems...))

	schemaSet := ast.NewSchemaSet()
	schemaSet.Put(ast.MustParseRef("schema.dockerfile"), map[string]interface{}{})
	schemaSet.Put(ast.MustParseRef("schema.cloud"), map[string]interface{}{})
	schemaSet.Put(ast.MustParseRef("schema.kubernetes"), map[string]interface{}{})

	compiler := ast.NewCompiler().
		WithUseTypeCheckAnnotations(true).
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithSchemas(schemaSet)

	compiler.Compile(baseModules)
	if compiler.Failed() {
		t.Fatal(compiler.Errors)
	}

	retriever := trivyRego.NewMetadataRetriever(compiler)

	ctx := context.Background()

	// now run the tests
	for _, module := range testModules {
		t.Run(module.Package.Path.String(), func(t *testing.T) {

			t.Run("schema", func(t *testing.T) {
				static, err := retriever.RetrieveMetadata(ctx, module)
				require.NoError(t, err)
				assert.Greater(t, len(static.InputOptions.Selectors), 0, "all rego files should specify at least one input selector")
				if static.Library { // lib files do not require avd IDs etc.
					return
				}
				assert.NotEmpty(t, static.AVDID, "all rego files should specify an AVD ID")
				assert.NotEmpty(t, static.Title, "all rego files should specify a title")
				assert.NotEmpty(t, static.Description, "all rego files should specify a description")
				assert.NotEmpty(t, static.Severity, "all rego files should specify a severity")
				assert.NotEmpty(t, static.ShortCode, "all rego files should specify a short code")
			})

			var hasTests bool
			for _, rule := range module.Rules {
				ruleName := rule.Head.Name.String()
				if !strings.HasPrefix(ruleName, "test_") {
					continue
				}
				hasTests = true
				t.Run(ruleName, func(t *testing.T) {
					regoOptions := []func(*rego.Rego){
						rego.Query(rule.Path().String()),
						rego.Compiler(compiler),
						rego.Schemas(schemaSet),
						rego.Trace(true),
					}

					instance := rego.New(regoOptions...)
					set, err := instance.Eval(ctx)
					require.NoError(t, err)

					tracer := bytes.NewBuffer(nil)
					rego.PrintTrace(tracer, instance)
					trace := tracer.String()

					assert.Len(t, set, 1, "assertion did not pass for: %s - trace follows:\n%s", rule.Path().String(), trace)
					for _, result := range set {
						assert.Len(t, result.Expressions, 1, "assertion did not pass for: %s - trace follows:\n%s", rule.Path().String(), trace)
						for _, expression := range result.Expressions {
							pass, ok := expression.Value.(bool)
							assert.Equal(t, true, ok, "test result was unexpected type")
							assert.Equal(t, true, pass, "test failed")
						}
					}

				})
			}
			assert.True(t, hasTests, "no tests found for module")
		})
	}
}
