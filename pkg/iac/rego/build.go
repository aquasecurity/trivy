package rego

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/util"

	"github.com/aquasecurity/trivy/pkg/iac/rego/schemas"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func BuildSchemaSetFromPolicies(policies map[string]*ast.Module, paths []string, fsys fs.FS) (*ast.SchemaSet, bool, error) {
	schemaSet := ast.NewSchemaSet()
	schemaSet.Put(ast.MustParseRef("schema.input"), make(map[string]interface{})) // for backwards compat only
	var customFound bool
	for _, policy := range policies {
		for _, annotation := range policy.Annotations {
			for _, ss := range annotation.Schemas {
				schemaName, err := ss.Schema.Ptr()
				if err != nil {
					continue
				}
				if schemaName != "input" {
					if schema, ok := schemas.SchemaMap[types.Source(schemaName)]; ok {
						customFound = true
						schemaSet.Put(ast.MustParseRef(ss.Schema.String()), util.MustUnmarshalJSON([]byte(schema)))
					} else {
						b, err := findSchemaInFS(paths, fsys, schemaName)
						if err != nil {
							return schemaSet, true, err
						}
						if b != nil {
							customFound = true
							schemaSet.Put(ast.MustParseRef(ss.Schema.String()), util.MustUnmarshalJSON(b))
						}
					}
				}
			}
		}
	}

	return schemaSet, customFound, nil
}

// findSchemaInFS tries to find the schema anywhere in the specified FS
func findSchemaInFS(paths []string, srcFS fs.FS, schemaName string) ([]byte, error) {
	var schema []byte
	for _, path := range paths {
		if err := fs.WalkDir(srcFS, sanitisePath(path), func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !IsJSONFile(info.Name()) {
				return nil
			}
			if info.Name() == schemaName+".json" {
				schema, err = fs.ReadFile(srcFS, filepath.ToSlash(path))
				if err != nil {
					return err
				}
				return nil
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return schema, nil
}

func IsJSONFile(name string) bool {
	return strings.HasSuffix(name, ".json")
}

func sanitisePath(path string) string {
	vol := filepath.VolumeName(path)
	path = strings.TrimPrefix(path, vol)
	return strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(path), "./"), "/")
}
