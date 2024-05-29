package vex

import (
	"encoding/json"
	"io"
	"os"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/hashicorp/go-multierror"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

// VEX represents Vulnerability Exploitability eXchange. It abstracts multiple VEX formats.
// Note: This is in the experimental stage and does not yet support many specifications.
// The implementation may change significantly.
type VEX interface {
	Filter(*types.Result, *core.BOM)
}

func New(filePath string, report types.Report) (VEX, error) {
	if filePath == "" {
		return nil, nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	var errs error
	// Try CycloneDX JSON
	if ok, err := sbom.IsCycloneDXJSON(f); err != nil {
		errs = multierror.Append(errs, err)
	} else if ok {
		return decodeCycloneDXJSON(f, report)
	}

	// Try OpenVEX
	if v, err := decodeOpenVEX(f); err != nil {
		errs = multierror.Append(errs, err)
	} else if v != nil {
		return v, nil
	}

	// Try CSAF
	if v, err := decodeCSAF(f); err != nil {
		errs = multierror.Append(errs, err)
	} else if v != nil {
		return v, nil
	}

	return nil, xerrors.Errorf("unable to load VEX: %w", errs)
}

func decodeCycloneDXJSON(r io.ReadSeeker, report types.Report) (VEX, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}
	vex, err := cyclonedx.DecodeJSON(r)
	if err != nil {
		return nil, xerrors.Errorf("json decode error: %w", err)
	}
	if report.ArtifactType != artifact.TypeCycloneDX {
		return nil, xerrors.New("CycloneDX VEX can be used with CycloneDX SBOM")
	}
	return newCycloneDX(report.BOM, vex), nil
}

func decodeOpenVEX(r io.ReadSeeker) (VEX, error) {
	// openvex/go-vex outputs log messages by default
	logrus.SetOutput(io.Discard)

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}
	var openVEX openvex.VEX
	if err := json.NewDecoder(r).Decode(&openVEX); err != nil {
		return nil, err
	}
	if openVEX.Context == "" {
		return nil, nil
	}
	return newOpenVEX(openVEX), nil
}

func decodeCSAF(r io.ReadSeeker) (VEX, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}
	var adv csaf.Advisory
	if err := json.NewDecoder(r).Decode(&adv); err != nil {
		return nil, err
	}
	if adv.Vulnerabilities == nil {
		return nil, nil
	}
	return newCSAF(adv), nil
}

type NotAffected func(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool)

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

		notAffectedFn := func(c, leaf *core.Component) bool {
			modified, notAffected := fn(vuln, c, leaf)
			if notAffected {
				result.ModifiedFindings = append(result.ModifiedFindings, modified)
				return true
			}
			return false
		}

		return reachRoot(c, bom.Components(), bom.Parents(), notAffectedFn)
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
