package conan

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type LockFile struct {
	GraphLock GraphLock `json:"graph_lock"`
	Requires  Requires  `json:"requires"`
}

type GraphLock struct {
	Nodes map[string]Node `json:"nodes"`
}

type Node struct {
	Ref      string   `json:"ref"`
	Requires []string `json:"requires"`
	xjson.Location
}
type Requires []Require

type Require struct {
	Dependency string
	xjson.Location
}

func (r *Require) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return json.UnmarshalDecode(dec, &r.Dependency)
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("conan"),
	}
}

func (p *Parser) parseV1(lock LockFile) ([]ftypes.Package, []ftypes.Dependency, error) {
	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	var directDeps []string
	if root, ok := lock.GraphLock.Nodes["0"]; ok {
		directDeps = root.Requires
	}

	// Parse packages
	parsed := make(map[string]ftypes.Package)
	for i, node := range lock.GraphLock.Nodes {
		if node.Ref == "" {
			continue
		}
		pkg, err := toPackage(node.Ref, node.Location)
		if err != nil {
			p.logger.Debug("Parse ref error", log.Err(err))
			continue
		}

		// Determine if the package is a direct dependency or not
		direct := slices.Contains(directDeps, i)
		pkg.Relationship = lo.Ternary(direct, ftypes.RelationshipDirect, ftypes.RelationshipIndirect)

		parsed[i] = pkg
	}

	// Parse dependency graph
	for i, node := range lock.GraphLock.Nodes {
		pkg, ok := parsed[i]
		if !ok {
			continue
		}

		var childDeps []string
		for _, req := range node.Requires {
			if child, ok := parsed[req]; ok {
				childDeps = append(childDeps, child.ID)
			}
		}
		if len(childDeps) != 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkg.ID,
				DependsOn: childDeps,
			})
		}

		pkgs = append(pkgs, pkg)
	}
	return pkgs, deps, nil
}

func (p *Parser) parseV2(lock LockFile) ([]ftypes.Package, []ftypes.Dependency, error) {
	var pkgs []ftypes.Package

	for _, req := range lock.Requires {
		pkg, err := toPackage(req.Dependency, req.Location)
		if err != nil {
			p.logger.Debug("Creating package entry from requirement failed", log.Err(err))
			continue
		}

		pkgs = append(pkgs, pkg)
	}
	return pkgs, []ftypes.Dependency{}, nil
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lock LockFile
	if err := xjson.UnmarshalRead(r, &lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode conan lock file: %w", err)
	}

	// try to parse requirements as conan v1.x
	if lock.GraphLock.Nodes != nil {
		p.logger.Debug("Handling conan lockfile as v1.x")
		return p.parseV1(lock)
	}
	// try to parse requirements as conan v2.x
	p.logger.Debug("Handling conan lockfile as v2.x")
	return p.parseV2(lock)
}

func parsePackage(text string) (string, string, error) {
	// full ref format: package/version@user/channel#rrev:package_id#prev
	// various examples:
	// 'pkga/0.1@user/testing'
	// 'pkgb/0.1.0'
	// 'pkgc/system'
	// 'pkgd/0.1.0#7dcb50c43a5a50d984c2e8fa5898bf18'
	ss := strings.Split(strings.Split(strings.Split(text, "@")[0], "#")[0], "/")
	if len(ss) != 2 {
		return "", "", xerrors.Errorf("Unable to determine conan dependency: %q", text)
	}
	return ss[0], ss[1], nil
}

func toPackage(pkg string, location xjson.Location) (ftypes.Package, error) {
	name, version, err := parsePackage(pkg)
	if err != nil {
		return ftypes.Package{}, err
	}
	return ftypes.Package{
		ID:        dependency.ID(ftypes.Conan, name, version),
		Name:      name,
		Version:   version,
		Locations: []ftypes.Location{ftypes.Location(location)},
	}, nil
}
