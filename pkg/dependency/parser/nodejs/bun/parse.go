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
	if err := xjson.UnmarshalJSONC(data, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	pkgs := make(map[string]ftypes.Package, len(lockFile.Packages))
	var deps ftypes.Dependencies

	directDeps := set.New[string]()
	devDeps := set.New[string]()

	for _, ws := range lockFile.Workspaces {
		directDeps.Append(lo.Keys(ws.Dependencies)...)
		directDeps.Append(lo.Keys(ws.DevDependencies)...)
		devDeps.Append(lo.Keys(ws.DevDependencies)...)
		directDeps.Append(lo.Keys(ws.PeerDependencies)...)
		directDeps.Append(lo.Keys(ws.OptionalDependencies)...)
	}
	for pkgName, parsed := range lockFile.Packages {
		pkgVersion := strings.TrimPrefix(parsed.Identifier, pkgName+"@")
		if strings.HasPrefix(pkgVersion, "workspace") {
			pkgVersion = lockFile.Workspaces[pkgName].Version
		}
		pkgId := packageID(pkgName, pkgVersion)
		isDirect := directDeps.Contains(pkgName)
		isDev := devDeps.Contains(pkgName)

		var depNames []string
		if depMap, ok := parsed.Meta["dependencies"].(map[string]any); ok {
			depNames = lo.Keys(depMap)
		}

		newPkg := ftypes.Package{
			ID:           pkgId,
			Name:         pkgName,
			Version:      pkgVersion,
			Relationship: lo.Ternary(isDirect, ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
			Dev:          isDev,
			DependsOn:    depNames,
			Locations:    []ftypes.Location{ftypes.Location(parsed.Location)},
		}
		pkgs[pkgName] = newPkg

		if len(depNames) > 0 {
			sort.Strings(depNames)
			deps = append(deps, ftypes.Dependency{
				ID:        pkgId,
				DependsOn: depNames,
			})
		}
	}
	// mark nested dependencies as dev
	for _, pkg := range pkgs {
		if pkg.Dev {
			for _, pkgDependency := range pkg.DependsOn {
				if devPackage, ok := pkgs[pkgDependency]; ok {
					devPackage.Dev = true
					pkgs[pkgDependency] = devPackage
				}
			}
		}
	}
	for i := range deps {
		deps[i].DependsOn = lo.Map(deps[i].DependsOn, func(dep string, _ int) string {
			return pkgs[dep].ID
		})
	}
	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(deps)
	return pkgSlice, deps, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Bun, name, version)
}
