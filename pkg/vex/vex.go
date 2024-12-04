package vex

import (
	"context"
	"errors"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

const (
	TypeFile       SourceType = "file"
	TypeRepository SourceType = "repo"
	TypeOCI        SourceType = "oci"
)

// VEX represents Vulnerability Exploitability eXchange. It abstracts multiple VEX formats.
// Note: This is in the experimental stage and does not yet support many specifications.
// The implementation may change significantly.
type VEX interface {
	NotAffected(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool)
}

type Client struct {
	VEXes []VEX
}

type Options struct {
	CacheDir string
	Sources  []Source
}

type SourceType string

type Source struct {
	Type     SourceType
	FilePath string // Used only for the file type
}

func NewSource(src string) Source {
	switch src {
	case "repository", "repo":
		return Source{Type: TypeRepository}
	case "oci":
		return Source{Type: TypeOCI}
	default:
		return Source{
			Type:     TypeFile,
			FilePath: src,
		}
	}
}

type NotAffected func(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool)

// Filter determines whether a detected vulnerability should be filtered out based on the provided VEX document.
// If the VEX document is passed and the vulnerability is either not affected or fixed according to the VEX statement,
// the vulnerability is filtered out.
func Filter(ctx context.Context, report *types.Report, opts Options) error {
	ctx = log.WithContextPrefix(ctx, "vex")
	client, err := New(ctx, report, opts)
	if err != nil {
		return xerrors.Errorf("VEX error: %w", err)
	} else if client == nil {
		return nil
	}

	// NOTE: This method call has a side effect on the report
	bom, err := sbomio.NewEncoder(core.Options{Parents: true}).Encode(*report)
	if err != nil {
		return xerrors.Errorf("unable to encode the SBOM: %w", err)
	}

	for i, result := range report.Results {
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		filterVulnerabilities(&report.Results[i], bom, client.NotAffected)
	}
	return nil
}

func New(ctx context.Context, report *types.Report, opts Options) (*Client, error) {
	var vexes []VEX
	for _, src := range opts.Sources {
		var v VEX
		var err error
		switch src.Type {
		case TypeFile:
			v, err = NewDocument(src.FilePath, report)
			if err != nil {
				return nil, xerrors.Errorf("unable to load VEX: %w", err)
			}
		case TypeRepository:
			v, err = NewRepositorySet(ctx, opts.CacheDir)
			if errors.Is(err, errNoRepository) {
				continue
			} else if err != nil {
				return nil, xerrors.Errorf("failed to create a vex repository set: %w", err)
			}
		case TypeOCI:
			v, err = NewOCI(report)
			if err != nil {
				return nil, xerrors.Errorf("VEX OCI error: %w", err)
			} else if v == nil {
				continue
			}
		default:
			log.Warn("Unsupported VEX source", log.String("type", string(src.Type)))
			continue
		}
		vexes = append(vexes, v)
	}

	if len(vexes) == 0 {
		log.DebugContext(ctx, "VEX filtering is disabled")
		return nil, nil
	}
	return &Client{VEXes: vexes}, nil
}

func (c *Client) NotAffected(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool) {
	for _, v := range c.VEXes {
		if m, notAffected := v.NotAffected(vuln, product, subComponent); notAffected {
			return m, true
		}
	}
	return types.ModifiedFinding{}, false
}

func filterVulnerabilities(result *types.Result, bom *core.BOM, fn NotAffected) {
	components := lo.MapEntries(bom.Components(), func(id uuid.UUID, component *core.Component) (string, *core.Component) {
		return component.PkgIdentifier.UID, component
	})

	result.Vulnerabilities = lo.Filter(result.Vulnerabilities, func(vuln types.DetectedVulnerability, _ int) bool {
		c, ok := components[vuln.PkgIdentifier.UID]
		if !ok {
			log.Error("Component not found", log.String("uid", vuln.PkgIdentifier.UID))
			return true // Should never reach here
		}

		var modified types.ModifiedFinding
		notAffectedFn := func(c, leaf *core.Component) bool {
			m, notAffected := fn(vuln, c, leaf)
			if notAffected {
				modified = m // Take the last modified finding if multiple VEX states "not affected"
			}
			return notAffected
		}

		if !reachRoot(c, bom.Components(), bom.Parents(), notAffectedFn) {
			result.ModifiedFindings = append(result.ModifiedFindings, modified)
			return false
		}
		return true
	})
}

// reachRoot traverses the component tree from the leaf to the root and returns true if the leaf reaches the root.
func reachRoot(leaf *core.Component, components map[uuid.UUID]*core.Component, parents map[uuid.UUID][]uuid.UUID,
	notAffected func(c, leaf *core.Component) bool) bool {

	if notAffected(leaf, nil) {
		return false
	}

	visited := make(map[uuid.UUID]bool)

	// Use Depth First Search (DFS)
	var dfs func(c *core.Component) bool
	dfs = func(c *core.Component) bool {
		// Call the function with the current component and the leaf component
		switch {
		case notAffected(c, leaf):
			return false
		case c.Root:
			return true
		case len(parents[c.ID()]) == 0:
			// Should never reach here as all components other than the root should have at least one parent.
			// If it does, it means the component tree is not connected due to a bug in the SBOM generation.
			// In this case, so as not to filter out all the vulnerabilities accidentally, return true for fail-safe.
			return true
		}

		visited[c.ID()] = true
		for _, parent := range parents[c.ID()] {
			if visited[parent] {
				continue
			}
			if dfs(components[parent]) {
				return true
			}
		}
		return false
	}

	return dfs(leaf)
}
