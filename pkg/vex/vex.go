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
	vexrepo "github.com/aquasecurity/trivy/pkg/vex/repo"
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
	VEXPath  string
}

type NotAffected func(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool)

// Filter determines whether a detected vulnerability should be filtered out based on the provided VEX document.
// If the VEX document is passed and the vulnerability is either not affected or fixed according to the VEX statement,
// the vulnerability is filtered out.
func Filter(ctx context.Context, report *types.Report, opts Options) error {
	client, err := New(ctx, report, opts)
	if err != nil {
		return xerrors.Errorf("VEX error: %w", err)
	} else if client == nil {
		return nil
	}

	bom, err := sbomio.NewEncoder(core.Options{}).Encode(*report)
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
	v, err := NewDocument(opts.VEXPath, report)
	if err != nil {
		return nil, xerrors.Errorf("unable to load VEX: %w", err)
	} else if v != nil {
		vexes = append(vexes, v)
	}

	rs, err := NewRepositorySet(ctx, opts.CacheDir)
	if !errors.Is(err, vexrepo.ErrNoConfig) && err != nil {
		return nil, xerrors.Errorf("failed to create a repository set: %w", err)
	} else if rs != nil {
		vexes = append(vexes, rs)
	}

	if len(vexes) == 0 {
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
		if notAffected(c, leaf) {
			return false
		} else if c.Root {
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
