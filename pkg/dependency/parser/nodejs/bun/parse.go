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
	Packages        map[string][]json.RawMessage `json:"packages"`
	Workspaces      map[string]Workspace         `json:"workspaces"`
	LockfileVersion int                          `json:"lockfileVersion"`
	xjson.Location
}

type Workspace struct {
	Name             string            `json:"name"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

type ParsedPackage struct {
	Identifier string
	Path       string
	Meta       map[string]any
	Integrity  string
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("bun"),
	}
}

func parsePackageEntry(raw []json.RawMessage) (ParsedPackage, error) {
	if len(raw) < 4 {
		return ParsedPackage{}, fmt.Errorf("invalid bun package entry: %v", raw)
	}
	var p ParsedPackage
	if err := json.Unmarshal(raw[0], &p.Identifier); err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw[1], &p.Path); err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw[2], &p.Meta); err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw[3], &p.Integrity); err != nil {
		return p, err
	}
	return p, nil
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
	for name, entry := range lockFile.Packages {
		parsed, err := parsePackageEntry(entry)
		if err != nil {
			p.logger.Warn("Failed to parse bun package entry", log.String("name", name), log.Err(err))
			continue
		}

		parts := strings.SplitN(parsed.Identifier, "@", 2)
		if len(parts) != 2 || parts[0] == "" {
			p.logger.Warn("Invalid package identifier", log.String("identifier", parsed.Identifier), log.Err(err))
			continue
		}
		pkgName := parts[0]
		pkgVersion := parts[1]
		pkgId := packageID(pkgName, pkgVersion)
		isDirect := directDeps.Contains(pkgName)

		var resolved string
		if r, ok := parsed.Meta["resolved"].(string); ok {
			resolved = r
		}

		var extRefs []ftypes.ExternalRef
		if resolved != "" {
			extRefs = append(extRefs, ftypes.ExternalRef{
				Type: ftypes.RefOther,
				URL:  resolved,
			})
		}
		newPkg := ftypes.Package{
			ID:                 pkgId,
			Name:               pkgName,
			Version:            pkgVersion,
			Relationship:       lo.Ternary(isDirect, ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
			Dev:                false,
			ExternalReferences: extRefs,
			Locations:          nil,
		}
		pkgs = append(pkgs, newPkg)

		var depList []string
		if depMap, ok := parsed.Meta["dependencies"].(map[string]any); ok {
			for depName := range depMap {
				if depEntry, ok := lockFile.Packages[depName]; ok {
					subParsed, err := parsePackageEntry(depEntry)
					if err != nil {
						depParts := strings.SplitN(subParsed.Identifier, "@", 2)
						if len(depParts) == 2 {
							depList = append(depList, packageID(depParts[0], depParts[1]))
						}
					}
				}
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
