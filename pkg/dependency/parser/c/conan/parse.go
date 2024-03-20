package conan

import (
	"io"
	"strings"

	"github.com/liamg/jfather"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type LockFileV1 struct {
	GraphLock GraphLock `json:"graph_lock"`
}

type GraphLock struct {
	Nodes map[string]Node `json:"nodes"`
}

type Node struct {
	Ref       string   `json:"ref"`
	Requires  []string `json:"requires"`
	StartLine int
	EndLine   int
}

type LockFileV2 struct {
	Requires []string `json:"requires"`
}

type Parser struct {
	logger *log.Logger
}


func NewParser() types.Parser {
	return &Parser{
		logger: log.WithPrefix("conan"),
	}
}

func (p *Parser) parseRequirementsV1(lock LockFileV1) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	var deps []types.Dependency
	var directDeps []string
	if root, ok := lock.GraphLock.Nodes["0"]; ok {
		directDeps = root.Requires
	}

	// Parse packages
	parsed := make(map[string]types.Library)
	for i, node := range lock.GraphLock.Nodes {
		if node.Ref == "" {
			continue
		}
		lib, err := parseRefV1(node)
		if err != nil {
			p.logger.Debug("Parse ref error", log.Err(err))
			continue
		}

		// Determine if the package is a direct dependency or not
		direct := slices.Contains(directDeps, i)
		lib.Indirect = !direct

		parsed[i] = lib
	}

	// Parse dependency graph
	for i, node := range lock.GraphLock.Nodes {
		lib, ok := parsed[i]
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
			deps = append(deps, types.Dependency{
				ID:        lib.ID,
				DependsOn: childDeps,
			})
		}

		libs = append(libs, lib)
	}
	return libs, deps, nil
}

func (p *Parser) parseRequirementsV2(lock LockFileV2) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library

	for _, req := range lock.Requires {
		lib, _ := parseRefV2(req)
		libs = append(libs, lib)
	}
	return libs, []types.Dependency{}, nil
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockV1 LockFileV1
	var lockV2 LockFileV2
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read conan lock file: %w", err)
	}

	// try to parse requirements as conan v1.x
	if err := jfather.Unmarshal(input, &lockV1); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode conan lock file: %w", err)
	}
	if lockV1.GraphLock.Nodes != nil {
		log.Logger.Debug("Handling conan lockfile as v1.x")
		return p.parseRequirementsV1(lockV1)
	} else {
		// try to parse requirements as conan v2.x
		log.Logger.Debug("Handling conan lockfile as v2.x")
		if err := jfather.Unmarshal(input, &lockV2); err != nil {
			return nil, nil, xerrors.Errorf("failed to decode conan lock file: %w", err)
		}
		return p.parseRequirementsV2(lockV2)
	}
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

func parseRefV1(node Node) (types.Library, error) {
	name, version, err := parsePackage(node.Ref)
	if err != nil {
		return types.Library{}, err
	}
	return types.Library{
		ID:      dependency.ID(ftypes.Conan, name, version),
		Name:    name,
		Version: version,
		Locations: []types.Location{
			{
				StartLine: node.StartLine,
				EndLine:   node.EndLine,
			},
		},
	}, nil
}

func parseRefV2(req string) (types.Library, error) {
	name, version, err := parsePackage(req)
	if err != nil {
		return types.Library{}, err
	}
	return types.Library{
		ID:      dependency.ID(ftypes.Conan, name, version),
		Name:    name,
		Version: version,
	}, nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (n *Node) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&n); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	n.StartLine = node.Range().Start.Line
	n.EndLine = node.Range().End.Line
	return nil
}
