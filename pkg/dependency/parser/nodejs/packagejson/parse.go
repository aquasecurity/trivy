package packagejson

import (
	"encoding/json"
	"io"
	"regexp"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var nameRegexp = regexp.MustCompile(`^(@[A-Za-z0-9-._]+/)?[A-Za-z0-9-._]+$`)

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	License              any               `json:"license"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	Workspaces           any               `json:"workspaces"`
}

type Package struct {
	ftypes.Package
	Dependencies         map[string]string
	OptionalDependencies map[string]string
	DevDependencies      map[string]string
	Workspaces           []string
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r io.Reader) (Package, error) {
	var pkgJSON packageJSON
	if err := json.NewDecoder(r).Decode(&pkgJSON); err != nil {
		return Package{}, xerrors.Errorf("JSON decode error: %w", err)
	}

	if !IsValidName(pkgJSON.Name) {
		return Package{}, xerrors.Errorf("Name can only contain URL-friendly characters")
	}

	var id string
	// Name and version fields are optional
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-json#name
	if pkgJSON.Name != "" && pkgJSON.Version != "" {
		id = dependency.ID(ftypes.NodePkg, pkgJSON.Name, pkgJSON.Version)
	}

	return Package{
		Package: ftypes.Package{
			ID:       id,
			Name:     pkgJSON.Name,
			Version:  pkgJSON.Version,
			Licenses: parseLicense(pkgJSON.License),
		},
		Dependencies:         pkgJSON.Dependencies,
		OptionalDependencies: pkgJSON.OptionalDependencies,
		DevDependencies:      pkgJSON.DevDependencies,
		Workspaces:           parseWorkspaces(pkgJSON.Workspaces),
	}, nil
}

func parseLicense(val any) []string {
	// the license isn't always a string, check for legacy struct if not string
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case map[string]any:
		if license, ok := v["type"]; ok {
			if s, ok := license.(string); ok && s != "" {
				return []string{s}
			}
		}
	}
	return nil
}

// parseWorkspaces returns slice of workspaces
func parseWorkspaces(val any) []string {
	// Workspaces support 2 types - https://github.com/SchemaStore/schemastore/blob/d9516961f8a5b0e65a457808070147b5a866f60b/src/schemas/json/package.json#L777
	switch ws := val.(type) {
	// Workspace as object (map[string][]string)
	// e.g. "workspaces": {"packages": ["packages/*", "plugins/*"]},
	case map[string]any:
		// Take only workspaces for `packages` - https://classic.yarnpkg.com/blog/2018/02/15/nohoist/
		if pkgsWorkspaces, ok := ws["packages"]; ok {
			return lo.Map(pkgsWorkspaces.([]any), func(workspace any, _ int) string {
				return workspace.(string)
			})
		}
	// Workspace as string array
	// e.g.   "workspaces": ["packages/*", "backend"],
	case []any:
		return lo.Map(ws, func(workspace any, _ int) string {
			return workspace.(string)
		})
	}
	return nil
}

func IsValidName(name string) bool {
	// Name is optional field
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-json#name
	if name == "" {
		return true
	}
	return nameRegexp.MatchString(name)
}
