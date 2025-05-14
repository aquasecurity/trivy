package bun

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
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

	var pkgs []ftypes.Package
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
	for _, parsed := range lockFile.Packages {
		idx := strings.LastIndex(parsed.Identifier, "@")
		if idx == -1 || idx == 0 {
			p.logger.Warn("Invalid package identifier", log.String("identifier", parsed.Identifier), log.Err(err))
			continue
		}

		pkgName := parsed.Identifier[:idx]
		pkgVersion := parsed.Identifier[idx+1:]
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
		pkgs = append(pkgs, newPkg)

		var depList []string
		if depMap, ok := parsed.Meta["dependencies"].(map[string]any); ok {
			for depName := range depMap {
				subParsed, ok := lockFile.Packages[depName]
				if !ok {
					continue
				}
				idx := strings.LastIndex(subParsed.Identifier, "@")
				if idx == -1 || idx == 0 {
					p.logger.Warn("Invalid package identifier", log.String("identifier", subParsed.Identifier), log.Err(err))
					continue
				}

				depName := subParsed.Identifier[:idx]
				depVersion := subParsed.Identifier[idx+1:]
				depList = append(depList, packageID(depName, depVersion))
			}
		}

		if len(depList) > 0 {
			sort.Strings(depList)
			deps = append(deps, ftypes.Dependency{
				ID:        pkgId,
				DependsOn: depList,
			})
		}
	}
	return utils.UniquePackages(pkgs), uniqueDeps(deps), nil
}

func uniqueDeps(deps []ftypes.Dependency) []ftypes.Dependency {
	var uniqDeps ftypes.Dependencies
	unique := set.New[string]()

	for _, dep := range deps {
		sort.Strings(dep.DependsOn)
		depKey := fmt.Sprintf("%s:%s", dep.ID, strings.Join(dep.DependsOn, ","))
		if !unique.Contains(depKey) {
			unique.Append(depKey)
			uniqDeps = append(uniqDeps, dep)
		}
	}

	sort.Sort(uniqDeps)
	return uniqDeps
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Npm, name, version)
}
