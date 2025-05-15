package bun

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

type ParsedPackage struct {
	Identifier string
	Path       string
	Meta       map[string]any
	Integrity  string
	xjson.Location
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("bun"),
	}
}

func (p *ParsedPackage) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("expected package format: %w", err)
	}
	if len(raw) < 1 {
		return fmt.Errorf("invalid package entry: not enough elements: %s", string(data))
	}

	if err := json.Unmarshal(raw[0], &p.Identifier); err != nil {
		return err
	}

	if len(raw) > 1 {
		if err := json.Unmarshal(raw[1], &p.Path); err != nil {
			return err
		}
	}

	if len(raw) > 2 {
		if err := json.Unmarshal(raw[2], &p.Meta); err != nil {
			return err
		}
	}
	if len(raw) > 3 {
		if err := json.Unmarshal(raw[3], &p.Integrity); err != nil {
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
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	pkgs := make(map[string]ftypes.Package, len(lockFile.Packages))
	var deps []ftypes.Dependency

	directDeps := set.New[string]()

	for _, ws := range lockFile.Workspaces {
		for name := range ws.Dependencies {
			directDeps.Append(name)
		}
		for name := range ws.DevDependencies {
			directDeps.Append(name)
		}
		for name := range ws.PeerDependencies {
			directDeps.Append(name)
		}
	}
	for pkgName, parsed := range lockFile.Packages {
		idx := strings.LastIndex(parsed.Identifier, "@")
		if idx == -1 || idx == 0 {
			p.logger.Warn("Invalid package identifier", log.String("identifier", parsed.Identifier), log.Err(err))
			continue
		}

		pkgVersion := parsed.Identifier[idx+1:]
		if strings.HasPrefix(pkgVersion, "workspace") {
			pkgVersion = lockFile.Workspaces[pkgName].Version
		}
		pkgId := packageID(pkgName, pkgVersion)
		isDirect := directDeps.Contains(pkgName)

		newPkg := ftypes.Package{
			ID:           pkgId,
			Name:         pkgName,
			Version:      pkgVersion,
			Relationship: lo.Ternary(isDirect, ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
			Dev:          false,
			Locations:    []ftypes.Location{ftypes.Location(parsed.Location)},
		}
		pkgs[pkgName] = newPkg

		var depNames []string
		if depMap, ok := parsed.Meta["dependencies"].(map[string]any); ok {
			depNames = lo.Keys(depMap)
		}

		if len(depNames) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkgId,
				DependsOn: depNames,
			})
		}
	}
	for i := range deps {
		deps[i].DependsOn = lo.Map(deps[i].DependsOn, func(dep string, _ int) string {
			return pkgs[dep].ID
		})
	}
	return utils.UniquePackages(lo.Values(pkgs)), deps, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Npm, name, version)
}
