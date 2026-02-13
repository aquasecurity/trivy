package vex

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

type CycloneDX struct {
	sbom       *core.BOM
	statements map[string]Statement
	logger     *log.Logger
}

type Statement struct {
	Affects       []string
	Status        types.FindingStatus
	Justification string
	OWASPRating   *types.OWASPRating
}

func newCycloneDX(sbom *core.BOM, vex *cdx.BOM) *CycloneDX {
	statements := make(map[string]Statement)
	for _, vuln := range lo.FromPtr(vex.Vulnerabilities) {
		affects := xslices.Map(lo.FromPtr(vuln.Affects), func(item cdx.Affects) string {
			return item.Ref
		})

		analysis := lo.FromPtr(vuln.Analysis)

		owaspRating := parseOWASPRating(vuln.Ratings)

		statements[vuln.ID] = Statement{
			Affects:       affects,
			Status:        cdxStatus(analysis.State),
			Justification: string(analysis.Justification),
			OWASPRating:   owaspRating,
		}
	}
	return &CycloneDX{
		sbom:       sbom,
		statements: statements,
		logger:     log.WithPrefix("vex").With(log.String("format", "CycloneDX")),
	}
}

// parseOWASPRating extracts the OWASP Risk Rating from CycloneDX VulnerabilityRatings
func parseOWASPRating(cdxRatings *[]cdx.VulnerabilityRating) *types.OWASPRating {
	if cdxRatings == nil || len(*cdxRatings) == 0 {
		return nil
	}

	// Look for OWASP rating specifically
	for _, r := range *cdxRatings {
		method := string(r.Method)
		if method != "OWASP" {
			continue
		}

		rating := &types.OWASPRating{
			Vector:   r.Vector,
			Severity: string(r.Severity),
		}

		if r.Score != nil {
			rating.Score = *r.Score
		}

		return rating
	}

	return nil
}

func (v *CycloneDX) NotAffected(vuln types.DetectedVulnerability, product, _ *core.Component) (types.ModifiedFinding, bool) {
	stmt, ok := v.statements[vuln.VulnerabilityID]
	if !ok {
		return types.ModifiedFinding{}, false
	}

	for _, affect := range stmt.Affects {
		if stmt.Status != types.FindingStatusNotAffected && stmt.Status != types.FindingStatusFixed {
			continue
		}

		// Affect must be BOM-Link at the moment
		link, err := cdx.ParseBOMLink(affect)
		if err != nil {
			v.logger.Warn("Unable to parse BOM-Link", log.String("affect", affect))
			continue
		}
		if v.sbom.SerialNumber != link.SerialNumber() || v.sbom.Version != link.Version() {
			v.logger.Warn("URN doesn't match with SBOM",
				log.String("serial number", link.SerialNumber()),
				log.Int("version", link.Version()))
			continue
		}
		if product.PkgIdentifier.Match(link.Reference()) {
			return types.NewModifiedFinding(vuln, stmt.Status, stmt.Justification, "CycloneDX VEX"), true
		}
	}
	return types.ModifiedFinding{}, false
}

// EnrichWithRatings enriches the vulnerability with OWASP Risk Rating from VEX if available
func (v *CycloneDX) EnrichWithRatings(vuln *types.DetectedVulnerability, product *core.Component) {
	stmt, ok := v.statements[vuln.VulnerabilityID]
	if !ok || stmt.OWASPRating == nil {
		return
	}

	// Check if this vulnerability affects the product
	for _, affect := range stmt.Affects {
		link, err := cdx.ParseBOMLink(affect)
		if err != nil {
			continue
		}
		if v.sbom.SerialNumber != link.SerialNumber() || v.sbom.Version != link.Version() {
			continue
		}
		if product.PkgIdentifier.Match(link.Reference()) {
			// Apply OWASP rating from VEX to this vulnerability
			vuln.OWASPRating = stmt.OWASPRating
			return
		}
	}
}

func cdxStatus(s cdx.ImpactAnalysisState) types.FindingStatus {
	switch s {
	case cdx.IASResolved, cdx.IASResolvedWithPedigree:
		return types.FindingStatusFixed
	case cdx.IASExploitable:
		return types.FindingStatusAffected
	case cdx.IASInTriage:
		return types.FindingStatusUnderInvestigation
	case cdx.IASFalsePositive, cdx.IASNotAffected:
		return types.FindingStatusNotAffected
	}
	return types.FindingStatusUnknown
}
