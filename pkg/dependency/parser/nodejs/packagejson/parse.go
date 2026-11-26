package packagejson

import (
	"encoding/json"
	"io"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var nameRegexp = regexp.MustCompile(`^(@[A-Za-z0-9-._]+/)?[A-Za-z0-9-._]+$`)

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
			Licenses: pkgJSON.License.Names(),
		},
		Dependencies:         pkgJSON.Dependencies,
		OptionalDependencies: pkgJSON.OptionalDependencies,
		DevDependencies:      pkgJSON.DevDependencies,
		Workspaces:           ParseWorkspaces(pkgJSON.Workspaces),
	}, nil
}

// ParseWorkspaces returns slice of workspaces
// `workspaces` field supports 2 types -
// string array and map with `packages` key only
// cf. https://github.com/npm/map-workspaces#usage
//
// The field is part of the scanned repository, so any shape a package.json can
// hold reaches here: a `packages` value that is not an array, or an array whose
// elements are not strings, is ignored rather than converted blindly.
func ParseWorkspaces(val any) []string {
	switch ws := val.(type) {
	// Workspace as object (map[string][]string)
	// e.g. "workspaces": {"packages": ["packages/*", "plugins/*"]},
	case map[string]any:
		// Take only workspaces for `packages`:
		// cf . https://github.com/npm/map-workspaces#usage
		pkgsWorkspaces, ok := ws["packages"]
		if !ok {
			return nil
		}
		list, ok := pkgsWorkspaces.([]any)
		if !ok {
			return nil
		}
		return stringElements(list)
	// Workspace as string array
	// e.g.   "workspaces": ["packages/*", "backend"],
	case []any:
		return stringElements(ws)
	}
	return nil
}

// stringElements keeps the string members of a decoded JSON array and drops the
// rest, so one malformed entry does not discard the whole list.
func stringElements(list []any) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func IsValidName(name string) bool {
	// Name is optional field
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-json#name
	if name == "" {
		return true
	}
	return nameRegexp.MatchString(name)
}
