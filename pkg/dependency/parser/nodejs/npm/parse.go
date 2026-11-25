package npm

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

const nodeModulesDir = "node_modules"

type LockFile struct {
	Dependencies    map[string]Dependency `json:"dependencies"`
	Packages        map[string]Package    `json:"packages"`
	LockfileVersion int                   `json:"lockfileVersion"`
}
type Dependency struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]Dependency `json:"dependencies"`
	Requires     map[string]string     `json:"requires"`
	Resolved     resolved              `json:"resolved"`
	xjson.Location
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// License is reused from packagejson because npm copies this field from package.json.
	// Modern npm versions normalize it, but legacy lockfiles still contain object/array shapes.
	License              packagejson.License `json:"license"`
	Dependencies         map[string]string   `json:"dependencies"`
	OptionalDependencies map[string]string   `json:"optionalDependencies"`
	DevDependencies      map[string]string   `json:"devDependencies"`
	PeerDependencies     map[string]string   `json:"peerDependencies"`
	Resolved             resolved            `json:"resolved"`
	Dev                  bool                `json:"dev"`
	Link                 bool                `json:"link"`
	Workspaces           any                 `json:"workspaces"`
	xjson.Location
}

// resolved represents the npm "resolved" field, which normally holds the tarball URL.
// npm 6 writes `false` instead of the URL for bundled dependencies inflated from the lockfile,
// because their metadata contains no registry address.
type resolved string

func (r *resolved) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch kind := dec.PeekKind(); kind {
	// "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"
	case jsontext.KindString:
		var s string
		if err := json.UnmarshalDecode(dec, &s); err != nil {
			return err
		}
		*r = resolved(s)
		return nil
	// `false` means the same as a missing field, so the package is left without a reference.
	case jsontext.KindTrue, jsontext.KindFalse:
		return dec.SkipValue()
	default:
		return xerrors.Errorf("unexpected `resolved` field type: %s", kind)
	}
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("npm"),
	}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	if err := xjson.UnmarshalRead(r, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	if lockFile.LockfileVersion == 1 {
		pkgs, deps := p.parseV1(lockFile.Dependencies, make(map[string]string))
		return utils.UniquePackages(pkgs), uniqueDeps(deps), nil
	}

	// v2+ package IDs are unique per dependency subgraph, so they must not be merged by name and version again.
	pkgs, deps := p.parseV2(lockFile.Packages)
	sort.Sort(ftypes.Packages(pkgs))
	return xslices.ZeroToNil(pkgs), uniqueDeps(deps), nil
}

// lockNode is a package installed at one lockfile path.
type lockNode struct {
	name     string
	children []string // lockfile paths of the resolved dependencies
}

func (p *Parser) parseV2(packages map[string]Package) ([]ftypes.Package, []ftypes.Dependency) {
	pkgs := make(map[string]ftypes.Package, len(packages)-1)
	var deps []ftypes.Dependency

	// Resolve links first
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json#packages
	p.resolveLinks(packages)

	directDeps := set.New[string]()
	for name, version := range lo.Assign(packages[""].Dependencies, packages[""].OptionalDependencies, packages[""].DevDependencies, packages[""].PeerDependencies) {
		pkgPath := joinPaths(nodeModulesDir, name)
		if _, ok := packages[pkgPath]; !ok {
			p.logger.Debug("Unable to find the direct dependency",
				log.String("name", name), log.String("version", version))
			continue
		}
		// Store the package paths of direct dependencies
		// e.g. node_modules/body-parser
		directDeps.Append(pkgPath)
	}

	nodes := p.lockNodes(packages)
	pkgPaths := slices.Sorted(maps.Keys(nodes))
	idOf := assignIDs(pkgPaths, nodes, packages)
	for _, pkgPath := range pkgPaths {
		pkg := packages[pkgPath]
		node := nodes[pkgPath]
		pkgID := idOf(pkgPath)

		var ref ftypes.ExternalRef
		if pkg.Resolved != "" {
			ref = ftypes.ExternalRef{
				Type: ftypes.RefOther,
				URL:  string(pkg.Resolved),
			}
		}

		pkgIndirect := isIndirectPkg(pkgPath, directDeps)

		// There are cases when similar packages use same dependencies
		// we need to add location for each these dependencies
		if savedPkg, ok := pkgs[pkgID]; ok {
			savedPkg.Dev = savedPkg.Dev && pkg.Dev
			if savedPkg.Relationship == ftypes.RelationshipIndirect && !pkgIndirect {
				savedPkg.Relationship = ftypes.RelationshipDirect
			}

			if ref.URL != "" && !slices.Contains(savedPkg.ExternalReferences, ref) {
				savedPkg.ExternalReferences = append(savedPkg.ExternalReferences, ref)
				sortExternalReferences(savedPkg.ExternalReferences)
			}

			savedPkg.Locations = append(savedPkg.Locations, ftypes.Location(pkg.Location))
			sort.Sort(savedPkg.Locations)

			// If for some reason license is missing in savedPkg, but exists in the current pkg, add it.
			if licenses := pkg.License.Names(); len(savedPkg.Licenses) == 0 && len(licenses) > 0 {
				savedPkg.Licenses = licenses
			}

			pkgs[pkgID] = savedPkg
			continue
		}

		licenses := pkg.License.Names()

		newPkg := ftypes.Package{
			ID:                 pkgID,
			Name:               node.name,
			Version:            pkg.Version,
			Licenses:           licenses,
			Relationship:       lo.Ternary(pkgIndirect, ftypes.RelationshipIndirect, ftypes.RelationshipDirect),
			Dev:                pkg.Dev,
			ExternalReferences: lo.Ternary(ref.URL != "", []ftypes.ExternalRef{ref}, nil),
			Locations:          []ftypes.Location{ftypes.Location(pkg.Location)},
		}
		pkgs[pkgID] = newPkg

		// Copies sharing an ID have identical subgraphs, so their children share IDs too.
		dependsOn := lo.Map(node.children, func(child string, _ int) string {
			return idOf(child)
		})
		if len(dependsOn) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        newPkg.ID,
				DependsOn: dependsOn,
			})
		}

	}

	return lo.Values(pkgs), deps
}

// lockNodes resolves every installed package and its dependencies to lockfile paths.
func (p *Parser) lockNodes(packages map[string]Package) map[string]lockNode {
	nodes := make(map[string]lockNode, len(packages))
	for pkgPath, pkg := range packages {
		if !strings.HasPrefix(pkgPath, nodeModulesDir) {
			continue
		}
		// pkg.Name exists when package name != folder name
		node := lockNode{name: cmp.Or(pkg.Name, p.pkgNameFromPath(pkgPath))}

		// npm builds graph using optional deps. e.g.:
		// └─┬ watchpack@1.7.5
		// ├─┬ chokidar@3.5.3 - optional dependency
		// │ └── glob-parent@5.1.
		for depName, depVersion := range lo.Assign(pkg.Dependencies, pkg.OptionalDependencies, pkg.PeerDependencies) {
			depPath, err := findDependsOn(pkgPath, depName, packages)
			if err != nil {
				p.logger.Debug("Unable to resolve the version",
					log.String("name", depName), log.String("version", depVersion))
				continue
			}
			node.children = append(node.children, depPath)
		}
		nodes[pkgPath] = node
	}
	return nodes
}

// assignIDs returns the package ID of each lockfile path. Copies of a package share an ID only
// when their whole dependency subgraphs are identical. Paths start grouped by name@version; a group
// splits while its members depend on different groups. This also terminates on dependency cycles.
// cf. https://github.com/aquasecurity/trivy/issues/8776
func assignIDs(pkgPaths []string, nodes map[string]lockNode, packages map[string]Package) func(pkgPath string) string {
	baseID := func(pkgPath string) string {
		return packageID(nodes[pkgPath].name, packages[pkgPath].Version)
	}

	// Each round reuses the previous round's group numbers, so no subgraph is walked twice.
	group, firstPaths := classify(pkgPaths, baseID)
	for {
		next, nextFirstPaths := classify(pkgPaths, func(pkgPath string) string {
			children := lo.Map(nodes[pkgPath].children, func(child string, _ int) int { return group[child] })
			slices.Sort(children)
			var key strings.Builder
			key.WriteString(strconv.Itoa(group[pkgPath]))
			for _, child := range children {
				key.WriteByte(',')
				key.WriteString(strconv.Itoa(child))
			}
			return key.String()
		})
		// No group split: the partition and its numbering are unchanged.
		if len(nextFirstPaths) == len(firstPaths) {
			break
		}
		group, firstPaths = next, nextFirstPaths
	}

	baseIDs := make([]string, len(firstPaths))
	groupsPerID := make(map[string]int)
	for g, pkgPath := range firstPaths {
		baseIDs[g] = baseID(pkgPath)
		groupsPerID[baseIDs[g]]++
	}
	return func(pkgPath string) string {
		g := group[pkgPath]
		if groupsPerID[baseIDs[g]] == 1 {
			return baseIDs[g]
		}
		sum := sha256.Sum256([]byte(firstPaths[g]))
		return baseIDs[g] + "::" + hex.EncodeToString(sum[:4])
	}
}

// classify numbers the distinct keys of paths in order of first appearance. It returns each
// path's number and, indexed by number, the first path that got it.
func classify(pkgPaths []string, key func(pkgPath string) string) (map[string]int, []string) {
	numbers := make(map[string]int)
	groups := make(map[string]int, len(pkgPaths))
	var firstPaths []string
	for _, pkgPath := range pkgPaths {
		k := key(pkgPath)
		n, ok := numbers[k]
		if !ok {
			n = len(firstPaths)
			numbers[k] = n
			firstPaths = append(firstPaths, pkgPath)
		}
		groups[pkgPath] = n
	}
	return groups, firstPaths
}

// for local package npm uses links. e.g.:
// function/func1 -> target of package
// node_modules/func1 -> link to target
// see `package-lock_v3_with_workspace.json` to better understanding
func (p *Parser) resolveLinks(packages map[string]Package) {
	links := lo.PickBy(packages, func(pkgPath string, pkg Package) bool {
		if !pkg.Link {
			return false
		}
		if pkg.Resolved == "" {
			p.logger.Warn("`package-lock.json` contains broken link with empty `resolved` field. This package will be skipped to avoid receiving an empty package", log.String("pkg", pkgPath))
			delete(packages, pkgPath)
			return false
		}
		return true
	})
	// Early return
	if len(links) == 0 {
		return
	}

	rootPkg := packages[""]
	if rootPkg.Dependencies == nil {
		rootPkg.Dependencies = make(map[string]string)
	}

	workspaces := packagejson.ParseWorkspaces(rootPkg.Workspaces)
	// Changing the map during the map iteration causes unexpected behavior,
	// so we need to iterate over the cloned `packages` map, but change the original `packages` map.
	for pkgPath, pkg := range maps.Clone(packages) {
		for linkPath, link := range links {
			// "packages/ui" must not claim "packages/ui-kit"
			rest, ok := strings.CutPrefix(pkgPath, string(link.Resolved))
			if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
				continue
			}
			// The target doesn't have the "resolved" field, so we need to copy it from the link.
			if pkg.Resolved == "" {
				pkg.Resolved = link.Resolved
			}

			// Resolve the link package so all packages are located under "node_modules".
			resolvedPath := linkPath + rest
			packages[resolvedPath] = pkg

			// Delete the target package
			delete(packages, pkgPath)

			if p.isWorkspace(pkgPath, workspaces) {
				rootPkg.Dependencies[p.pkgNameFromPath(linkPath)] = pkg.Version
			}
			break
		}
	}
	packages[""] = rootPkg
}

func (p *Parser) isWorkspace(pkgPath string, workspaces []string) bool {
	for _, workspace := range workspaces {
		if match, err := path.Match(workspace, pkgPath); err != nil {
			p.logger.Debug("Unable to parse workspace",
				log.String("workspace", workspace), log.String("pkg_path", pkgPath))
		} else if match {
			return true
		}
	}
	return false
}

func findDependsOn(pkgPath, depName string, packages map[string]Package) (string, error) {
	depPath := joinPaths(pkgPath, nodeModulesDir)
	paths := strings.Split(depPath, "/")
	// Try to resolve the version with the nearest directory
	// e.g. for pkgPath == `node_modules/body-parser/node_modules/debug`, depName == `ms`:
	//    - "node_modules/body-parser/node_modules/debug/node_modules/ms"
	//    - "node_modules/body-parser/node_modules/ms"
	//    - "node_modules/ms"
	for i, v := range slices.Backward(paths) {
		if v != nodeModulesDir {
			continue
		}
		modulePath := joinPaths(paths[:i+1]...)
		modulePath = joinPaths(modulePath, depName)

		if _, ok := packages[modulePath]; ok {
			return modulePath, nil
		}
	}

	// It should not reach here.
	return "", xerrors.Errorf("can't find dependsOn for %s", depName)
}

func (p *Parser) parseV1(dependencies map[string]Dependency, versions map[string]string) ([]ftypes.Package, []ftypes.Dependency) {
	// Update package name and version mapping.
	for pkgName, dep := range dependencies {
		// Overwrite the existing package version so that the nested version can take precedence.
		versions[pkgName] = dep.Version
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	for pkgName, dep := range dependencies {
		var refs []ftypes.ExternalRef
		// Bundled dependencies have no registry address, so the `resolved` field is empty for them.
		if dep.Resolved != "" {
			refs = []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  string(dep.Resolved),
				},
			}
		}

		pkg := ftypes.Package{
			ID:                 packageID(pkgName, dep.Version),
			Name:               pkgName,
			Version:            dep.Version,
			Dev:                dep.Dev,
			Relationship:       ftypes.RelationshipUnknown, // lockfile v1 schema doesn't have information about direct dependencies
			ExternalReferences: refs,
			Locations:          []ftypes.Location{ftypes.Location(dep.Location)},
		}
		pkgs = append(pkgs, pkg)

		dependsOn := make([]string, 0, len(dep.Requires))
		for pName, requiredVer := range dep.Requires {
			// Try to resolve the version with nested dependencies first
			if resolvedDep, ok := dep.Dependencies[pName]; ok {
				pkgID := packageID(pName, resolvedDep.Version)
				dependsOn = append(dependsOn, pkgID)
				continue
			}

			// Try to resolve the version with the higher level dependencies
			if ver, ok := versions[pName]; ok {
				dependsOn = append(dependsOn, packageID(pName, ver))
				continue
			}

			// It should not reach here.
			p.logger.Warn("Unable to resolve the version",
				log.String("name", pName), log.String("version", requiredVer))
		}

		if len(dependsOn) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        packageID(pkg.Name, pkg.Version),
				DependsOn: dependsOn,
			})
		}

		if dep.Dependencies != nil {
			// Recursion
			childpkgs, childDeps := p.parseV1(dep.Dependencies, maps.Clone(versions))
			pkgs = append(pkgs, childpkgs...)
			deps = append(deps, childDeps...)
		}
	}

	return pkgs, deps
}

func (p *Parser) pkgNameFromPath(pkgPath string) string {
	// lock file contains path to dependency in `node_modules`. e.g.:
	// node_modules/string-width
	// node_modules/string-width/node_modules/strip-ansi
	// we renamed to `node_modules` directory prefixes `workspace` when resolving Links
	// node_modules/function1
	// node_modules/nested_func/node_modules/debug
	_, pkgName, found := strings.CutLast(pkgPath, nodeModulesDir)
	if !found {
		p.logger.Warn("Package path doesn't have `node_modules` prefix", log.String("pkg_path", pkgPath))
		return pkgPath
	}

	pkgName = strings.TrimPrefix(pkgName, "/")
	if pkgName == "" {
		p.logger.Warn("Invalid package-lock.json file. Package path doesn't have package name suffix", log.String("pkg_path", pkgPath))
		return ""
	}

	return pkgName
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

func isIndirectPkg(pkgPath string, directDeps set.Set[string]) bool {
	// A project can contain 2 different versions of the same dependency.
	// e.g. `node_modules/string-width/node_modules/strip-ansi` and `node_modules/string-ansi`
	// direct dependencies always have root path (`node_modules/<pkg_name>`)
	if directDeps.Contains(pkgPath) {
		return false
	}
	return true
}

func joinPaths(paths ...string) string {
	return strings.Join(paths, "/")
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Npm, name, version)
}

func sortExternalReferences(refs []ftypes.ExternalRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Type != refs[j].Type {
			return refs[i].Type < refs[j].Type
		}
		return refs[i].URL < refs[j].URL
	})
}
