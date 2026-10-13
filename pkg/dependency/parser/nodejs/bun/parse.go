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

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/dependency"
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

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("bun"),
	}
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

	// pkgs and deps are keyed by the install path (the key in `packages`),
	// e.g. "debug" or "send/debug" for a nested copy.
	pkgs := make(map[string]ftypes.Package, len(lockFile.Packages))
	depNames := make(map[string][]string)

	prodDirectDeps := set.New[string]()
	devDirectDeps := set.New[string]()

	for _, ws := range lockFile.Workspaces {
		prodDirectDeps.Append(lo.Keys(ws.Dependencies)...)
		prodDirectDeps.Append(lo.Keys(ws.PeerDependencies)...)
		prodDirectDeps.Append(lo.Keys(ws.OptionalDependencies)...)
		devDirectDeps.Append(lo.Keys(ws.DevDependencies)...)
	}
	for pkgPath, parsed := range lockFile.Packages {
		// The map key is an install path, which for deduped/nested dependencies
		// is "parent/child" (e.g. "glob/minimatch") rather than the package name.
		// The name and version come from the identifier ("minimatch@9.0.5").
		name, pkgVersion := splitIdentifier(parsed.Identifier)
		if name == "" {
			p.logger.Debug("Skip package with empty name", log.String("pkg_path", pkgPath))
			continue
		}
		if strings.HasPrefix(pkgVersion, "workspace") {
			pkgVersion = lockFile.Workspaces[pkgPath].Version
		}
		if pkgVersion != "" {
			if _, err := semver.Parse(pkgVersion); err != nil {
				p.logger.Debug("Skip non-semver package version", log.String("pkg_path", pkgPath),
					log.String("version", pkgVersion), log.Err(err))
				pkgVersion = ""
			}
		}
		isDirect := prodDirectDeps.Contains(pkgPath) || devDirectDeps.Contains(pkgPath)

		relationship := ftypes.RelationshipIndirect
		if _, ok := lockFile.Workspaces[pkgPath]; ok {
			relationship = ftypes.RelationshipWorkspace
		} else if isDirect {
			relationship = ftypes.RelationshipDirect
		}

		pkgs[pkgPath] = ftypes.Package{
			ID:           packageID(name, pkgVersion),
			Name:         name,
			Version:      pkgVersion,
			Relationship: relationship,
			Dev:          true, // Mark all dependencies as Dev. We will handle them later.
			Locations:    []ftypes.Location{ftypes.Location(parsed.Location)},
		}

		if depMap, ok := parsed.Meta["dependencies"].(map[string]any); ok && len(depMap) > 0 {
			depNames[pkgPath] = lo.Keys(depMap)
		}
	}

	// Resolve dependency names to install paths once all packages are collected,
	// so that a nested copy is used instead of the hoisted one when it exists.
	deps := make(map[string][]string, len(depNames))
	for pkgPath, names := range depNames {
		var dependsOn []string
		for _, depName := range names {
			depPath, ok := resolveDependency(pkgPath, depName, pkgs)
			if !ok {
				p.logger.Debug("Unable to resolve the dependency", log.String("pkg_path", pkgPath),
					log.String("dependency", depName))
				continue
			}
			dependsOn = append(dependsOn, depPath)
		}
		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps[pkgPath] = dependsOn
		}
	}

	for pkgPath, pkg := range pkgs {
		// Workspaces are always prod deps.
		if pkg.Relationship == ftypes.RelationshipWorkspace {
			pkg.Dev = false
			pkgs[pkgPath] = pkg
			continue
		}
		if pkg.Relationship != ftypes.RelationshipDirect || !prodDirectDeps.Contains(pkgPath) {
			continue
		}
		walkProdPackages(pkgPath, pkgs, deps, set.New[string]())
	}

	pkgSlice, depSlice := mergePackages(pkgs, deps)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(ftypes.Dependencies(depSlice))
	return pkgSlice, depSlice, nil
}

// walkProdPackages marks all packages in the dependency tree of the given package as prod packages (Dev == false).
func walkProdPackages(pkgPath string, pkgs map[string]ftypes.Package, deps map[string][]string, visited set.Set[string]) {
	if visited.Contains(pkgPath) {
		return
	}

	// Disable Dev field for prod pkgs.
	pkg := pkgs[pkgPath]
	pkg.Dev = false
	pkgs[pkgPath] = pkg

	visited.Append(pkgPath)
	for _, dep := range deps[pkgPath] {
		walkProdPackages(dep, pkgs, deps, visited)
	}
}

// resolveDependency returns the install path of the dependency `depName` of the package at `pkgPath`.
// It follows the Node.js resolution: the nearest nested copy wins, then the top-level one.
// e.g. for pkgPath == "send/debug" and depName == "ms":
//   - "send/debug/ms"
//   - "send/ms"
//   - "ms"
func resolveDependency(pkgPath, depName string, pkgs map[string]ftypes.Package) (string, bool) {
	segments := splitPath(pkgPath)
	for i := len(segments); i > 0; i-- {
		depPath := strings.Join(segments[:i], "/") + "/" + depName
		if _, ok := pkgs[depPath]; ok {
			return depPath, true
		}
	}
	if _, ok := pkgs[depName]; ok {
		return depName, true
	}
	return "", false
}

// splitPath splits an install path into package names.
// A scoped name is a single segment, e.g. "glob/@isaacs/cliui" -> ["glob", "@isaacs/cliui"].
func splitPath(pkgPath string) []string {
	var segments []string
	parts := strings.Split(pkgPath, "/")
	for i := 0; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
			segments = append(segments, parts[i]+"/"+parts[i+1])
			i++
			continue
		}
		segments = append(segments, parts[i])
	}
	return segments
}

// mergePackages merges packages installed under several paths with the same ID
// (e.g. "express/debug" and "send/debug"), as the npm parser does.
func mergePackages(pkgs map[string]ftypes.Package, deps map[string][]string) ([]ftypes.Package, []ftypes.Dependency) {
	merged := make(map[string]ftypes.Package, len(pkgs))
	dependsOn := make(map[string]set.Set[string])
	for pkgPath, pkg := range pkgs {
		if savedPkg, ok := merged[pkg.ID]; ok {
			savedPkg.Dev = savedPkg.Dev && pkg.Dev
			if savedPkg.Relationship == ftypes.RelationshipIndirect && pkg.Relationship == ftypes.RelationshipDirect {
				savedPkg.Relationship = ftypes.RelationshipDirect
			}
			savedPkg.Locations = append(savedPkg.Locations, pkg.Locations...)
			sort.Sort(savedPkg.Locations)
			pkg = savedPkg
		}
		merged[pkg.ID] = pkg

		for _, depPath := range deps[pkgPath] {
			if _, ok := dependsOn[pkg.ID]; !ok {
				dependsOn[pkg.ID] = set.New[string]()
			}
			dependsOn[pkg.ID].Append(pkgs[depPath].ID)
		}
	}

	depSlice := lo.MapToSlice(dependsOn, func(id string, depIDs set.Set[string]) ftypes.Dependency {
		ids := depIDs.Items()
		sort.Strings(ids)
		return ftypes.Dependency{
			ID:        id,
			DependsOn: ids,
		}
	})
	return lo.Values(merged), depSlice
}

// splitIdentifier splits a bun lockfile package identifier ("name@version")
// into its name and version. The version can itself contain "@" (e.g. the git
// dependency "adm-zip@git+ssh://git@github.com/..."), so it splits at the first
// "@" after an optional leading "@" of a scoped name ("@types/node@22.15.18").
func splitIdentifier(identifier string) (name, version string) {
	rest, scoped := strings.CutPrefix(identifier, "@")
	name, version, _ = strings.Cut(rest, "@")
	if scoped {
		name = "@" + name
	}
	return name, version
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Bun, name, version)
}
