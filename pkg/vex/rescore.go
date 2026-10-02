package vex

import (
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

// CSAFSeveritySource is the severity source ID of scores taken from CSAF documents.
// It can be specified in "--vuln-severity-source" to enable rescoring.
const CSAFSeveritySource dbTypes.SourceID = "csaf"

// SeverityOverride represents a severity and CVSS score provided by a VEX document.
type SeverityOverride struct {
	Severity dbTypes.Severity
	Source   dbTypes.SourceID
	CVSS     dbTypes.CVSS
	Document string // The location of the VEX document providing the score
}

// Rescorer is implemented by VEX formats that can provide severity scores (e.g. CSAF).
type Rescorer interface {
	Rescore(vuln types.DetectedVulnerability, product, subComponent *core.Component) (SeverityOverride, bool)
}

// RescoreReport overrides the severity and CVSS of detected vulnerabilities with scores from the VEX sources.
// The CSAF score is applied only if "csaf" precedes the source that determined the current severity in severitySources.
// It returns the generated BOM so that it can be reused for VEX filtering.
func (c *Client) RescoreReport(report *types.Report, severitySources []dbTypes.SourceID) (*core.BOM, error) {
	if c == nil || !lo.ContainsBy(c.VEXes, isRescorer) {
		log.WithPrefix("vex").Warn("No VEX sources supporting CSAF scores are specified, so the severity source is ignored",
			log.String("severity-source", string(CSAFSeveritySource)))
		return nil, nil
	}

	// NOTE: This method call has a side effect on the report, the same as VEX filtering.
	bom, err := sbomio.NewEncoder(sbomio.WithParents(), sbomio.ForceRegenerate()).Encode(*report)
	if err != nil {
		return nil, xerrors.Errorf("unable to encode the SBOM: %w", err)
	}

	for i := range report.Results {
		rescoreVulnerabilities(&report.Results[i], bom, severitySources, c.Rescore)
	}
	return bom, nil
}

// Rescore returns the first severity override provided by the VEX sources.
func (c *Client) Rescore(vuln types.DetectedVulnerability, product, subComponent *core.Component) (SeverityOverride, bool) {
	return rescore(c.VEXes, vuln, product, subComponent)
}

// rescore returns the first severity override provided by the given VEX documents supporting rescoring.
func rescore(vexes []VEX, vuln types.DetectedVulnerability, product, subComponent *core.Component) (SeverityOverride, bool) {
	for _, v := range vexes {
		r, ok := v.(Rescorer)
		if !ok {
			continue
		}
		if override, found := r.Rescore(vuln, product, subComponent); found {
			return override, true
		}
	}
	return SeverityOverride{}, false
}

func isRescorer(v VEX) bool {
	_, ok := v.(Rescorer)
	return ok
}

func rescoreVulnerabilities(result *types.Result, bom *core.BOM, severitySources []dbTypes.SourceID,
	fn func(vuln types.DetectedVulnerability, product, subComponent *core.Component) (SeverityOverride, bool)) {
	components := lo.MapEntries(bom.Components(), func(_ uuid.UUID, component *core.Component) (string, *core.Component) {
		return component.PkgIdentifier.UID, component
	})

	for i, vuln := range result.Vulnerabilities {
		if !preferCSAF(vuln, severitySources) {
			continue
		}

		c, ok := components[vuln.PkgIdentifier.UID]
		if !ok {
			log.Error("Component not found", log.String("uid", vuln.PkgIdentifier.UID))
			continue
		}

		override, ok := findOverride(c, bom.Components(), bom.Parents(), func(product, leaf *core.Component) (SeverityOverride, bool) {
			return fn(vuln, product, leaf)
		})
		if !ok {
			continue
		}

		log.WithPrefix("vex").Info("Rescored the detected vulnerability",
			log.String("vulnerability-id", vuln.VulnerabilityID), log.String("package", vuln.PkgName),
			log.String("from", vuln.Severity), log.String("to", override.Severity.String()),
			log.String("source", override.Document))
		result.Vulnerabilities[i] = applySeverityOverride(vuln, override)
	}
}

// preferCSAF reports whether "csaf" precedes the source that determined the current severity.
func preferCSAF(vuln types.DetectedVulnerability, severitySources []dbTypes.SourceID) bool {
	for _, source := range severitySources {
		switch {
		case source == CSAFSeveritySource:
			return true
		case source == "auto":
			return false
		case lo.HasKey(vuln.VendorSeverity, source):
			return false
		}
	}
	return false
}

// findOverride returns the override for the vulnerable component itself if any.
// Otherwise, it returns the highest override among the nearest matching ancestors.
func findOverride(leaf *core.Component, components map[uuid.UUID]*core.Component, parents map[uuid.UUID][]uuid.UUID,
	fn func(product, leaf *core.Component) (SeverityOverride, bool)) (SeverityOverride, bool) {
	if override, ok := fn(leaf, nil); ok {
		return override, true
	}

	visited := set.New[uuid.UUID](leaf.ID())
	level := []uuid.UUID{leaf.ID()}
	for len(level) > 0 {
		var best SeverityOverride
		var found bool
		var next []uuid.UUID
		for _, id := range level {
			for _, parent := range parents[id] {
				if visited.Contains(parent) {
					continue
				}
				visited.Append(parent)

				c, ok := components[parent]
				if !ok {
					continue
				}
				next = append(next, parent)
				if override, ok := fn(c, leaf); ok && (!found || higherSeverityOverride(override, best)) {
					best = override
					found = true
				}
			}
		}
		if found {
			return best, true
		}
		level = next
	}
	return SeverityOverride{}, false
}

func higherSeverityOverride(candidate, current SeverityOverride) bool {
	if candidate.Severity != current.Severity {
		return candidate.Severity > current.Severity
	}
	return cvssBaseScore(candidate.CVSS) > cvssBaseScore(current.CVSS)
}

func cvssBaseScore(cvss dbTypes.CVSS) float64 {
	return max(cvss.V40Score, cvss.V3Score, cvss.V2Score)
}

func applySeverityOverride(vuln types.DetectedVulnerability, override SeverityOverride) types.DetectedVulnerability {
	vuln.Severity = override.Severity.String()
	vuln.SeveritySource = override.Source

	// Copy maps to avoid modifying the vulnerability details shared with other findings
	vuln.VendorSeverity = lo.Assign(vuln.VendorSeverity, dbTypes.VendorSeverity{override.Source: override.Severity})
	if override.CVSS != (dbTypes.CVSS{}) {
		vuln.CVSS = lo.Assign(vuln.CVSS, dbTypes.VendorCVSS{override.Source: override.CVSS})
	}
	return vuln
}

// parseCVSSSeverity converts a CVSS qualitative severity rating into a Trivy severity.
// CVSS "NONE" is mapped to UNKNOWN as Trivy has no equivalent.
func parseCVSSSeverity(severity string) (dbTypes.Severity, bool) {
	severity = strings.ToUpper(severity)
	if severity == "NONE" {
		return dbTypes.SeverityUnknown, true
	}
	s, err := dbTypes.NewSeverity(severity)
	if err != nil {
		return dbTypes.SeverityUnknown, false
	}
	return s, true
}
