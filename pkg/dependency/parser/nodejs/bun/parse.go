package bun

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"sort"
	"strings"

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

	// When package contains only package field [pkg: string]
	// cf. https://github.com/oven-sh/bun/blob/61e03a275885b9b48f7a28f6dfbbbe1156eedca6/packages/bun-types/bun.d.ts#L7751
	if len(raw) == 1 {
		return nil
	}

	// Meta can be 2 or 3 array elements
	// [pkg: string, info: BunLockFilePackageInfo]
	// [pkg: string, info: BunLockFilePackageInfo, bunTag: string]
	// [pkg: string, info: Pick<BunLockFileBasePackageInfo, "bin" | "binDir">]
	// [pkg: string, registry: string, info: BunLockFilePackageInfo, integrity: string]
	// cf.https://github.com/oven-sh/bun/blob/61e03a275885b9b48f7a28f6dfbbbe1156eedca6/packages/bun-types/bun.d.ts#L7745-L7755
	metaRaw := raw[1]
	if len(raw) > 3 {
		metaRaw = raw[2]
	}
	return json.Unmarshal(metaRaw, &p.Meta)
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
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

	prodDirectDeps := set.New[string]()
	devDirectDeps := set.New[string]()

	for _, ws := range lockFile.Workspaces {
		prodDirectDeps.Append(lo.Keys(ws.Dependencies)...)
		prodDirectDeps.Append(lo.Keys(ws.PeerDependencies)...)
		prodDirectDeps.Append(lo.Keys(ws.OptionalDependencies)...)
		devDirectDeps.Append(lo.Keys(ws.DevDependencies)...)
	}
	for pkgName, parsed := range lockFile.Packages {
		pkgVersion := strings.TrimPrefix(parsed.Identifier, pkgName+"@")
		if strings.HasPrefix(pkgVersion, "workspace") {
			pkgVersion = lockFile.Workspaces[pkgName].Version
		}
		pkgId := packageID(pkgName, pkgVersion)
		isDirect := prodDirectDeps.Contains(pkgName) || devDirectDeps.Contains(pkgName)

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
		id := pkgs[depName]
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
