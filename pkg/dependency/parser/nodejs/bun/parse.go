package bun

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type LockFile struct {
	Packages        map[string]ParsedPackage `json:"packages"`
	Workspaces      map[string]Workspace     `json:"workspaces"`
	LockfileVersion int                      `json:"lockfileVersion"`
}

type Workspace struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type ParsedPackage struct {
	Identifier string
	Meta       map[string]any
	xjson.Location
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *ParsedPackage) UnmarshalJSON(data []byte) error {
	var raw []jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("expected package format: %w", err)
	}
	if len(raw) < 1 {
		return fmt.Errorf("invalid package entry: not enough elements: %s", string(data))
	}

	if err := json.Unmarshal(raw[0], &p.Identifier); err != nil {
		return err
	}

	if len(raw) > 2 {
		if err := json.Unmarshal(raw[2], &p.Meta); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("file read error: %w", err)
	}
	if err = xjson.UnmarshalJSONC(data, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	pkgs := make(map[string]ftypes.Package, len(lockFile.Packages))
	deps := make(map[string][]string)

	directDeps := set.New[string]()
	prodDirectDeps := set.New[string]()

	for _, ws := range lockFile.Workspaces {
		directDeps.Append(lo.Keys(ws.Dependencies)...)
		directDeps.Append(lo.Keys(ws.PeerDependencies)...)
		directDeps.Append(lo.Keys(ws.OptionalDependencies)...)
		prodDirectDeps = directDeps.Clone()
		directDeps.Append(lo.Keys(ws.DevDependencies)...)
	}
	for pkgName, parsed := range lockFile.Packages {
		pkgVersion := strings.TrimPrefix(parsed.Identifier, pkgName+"@")
		if strings.HasPrefix(pkgVersion, "workspace") {
			pkgVersion = lockFile.Workspaces[pkgName].Version
		}
		pkgId := packageID(pkgName, pkgVersion)
		isDirect := directDeps.Contains(pkgName)

		relationship := ftypes.RelationshipIndirect
		if _, ok := lockFile.Workspaces[pkgName]; ok {
			relationship = ftypes.RelationshipWorkspace
		} else if isDirect {
			relationship = ftypes.RelationshipDirect
		}

		newPkg := ftypes.Package{
			ID:           pkgId,
			Name:         pkgName,
			Version:      pkgVersion,
			Relationship: relationship,
			Dev:          true, // Mark all dependencies as Dev. We will handle them later.
			Locations:    []ftypes.Location{ftypes.Location(parsed.Location)},
		}
		pkgs[pkgName] = newPkg

		var dependsOn []string
		if depMap, ok := parsed.Meta["dependencies"].(map[string]any); ok {
			dependsOn = lo.Keys(depMap)
		}

		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps[pkgName] = dependsOn
		}
	}

	for _, pkg := range pkgs {
		// Workspaces are always prod deps.
		if pkg.Relationship == ftypes.RelationshipWorkspace {
			pkg.Dev = false
			pkgs[pkg.Name] = pkg
			continue
		}
		if pkg.Relationship != ftypes.RelationshipDirect || !prodDirectDeps.Contains(pkg.Name) {
			continue
		}
		walkProdPackages(pkg.Name, pkgs, deps, set.New[string]())
	}

	depSlice := lo.MapToSlice(deps, func(depName string, dependsOn []string) ftypes.Dependency {
		id, _ := pkgs[depName]
		dependsOnIDs := make([]string, 0, len(dependsOn))
		for _, d := range dependsOn {
			dependsOnIDs = append(dependsOnIDs, pkgs[d].ID)
		}
		return ftypes.Dependency{
			ID:        id.ID,
			DependsOn: dependsOnIDs,
		}
	})
	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(ftypes.Dependencies(depSlice))
	return pkgSlice, depSlice, nil
}

// walkProdPackages marks all packages in the dependency tree of the given package as prod packages (Dev == false).
func walkProdPackages(pkgName string, pkgs map[string]ftypes.Package, deps map[string][]string, visited set.Set[string]) {
	if visited.Contains(pkgName) {
		return
	}

	// Disable Dev field for prod pkgs.
	pkg := pkgs[pkgName]
	pkg.Dev = false
	pkgs[pkgName] = pkg

	visited.Append(pkgName)
	for _, dep := range deps[pkgName] {
		walkProdPackages(dep, pkgs, deps, visited)
	}
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Bun, name, version)
}
