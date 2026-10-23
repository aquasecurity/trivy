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
	statements map[string][]Statement
	logger     *log.Logger
}

type Statement struct {
	Affects       []string
	Status        types.FindingStatus
	Justification string
}

func newCycloneDX(sbom *core.BOM, vex *cdx.BOM) *CycloneDX {
	statements := make(map[string][]Statement)
	for _, vuln := range lo.FromPtr(vex.Vulnerabilities) {
		affects := xslices.Map(lo.FromPtr(vuln.Affects), func(item cdx.Affects) string {
			return item.Ref
		})

		// A CycloneDX document can contain several vulnerability objects
		// sharing the same ID, e.g. to analyze the same vulnerability
		// per component. Keep all of them so no statement is lost.
		// cf. https://github.com/aquasecurity/trivy/issues/11396
		analysis := lo.FromPtr(vuln.Analysis)
		statements[vuln.ID] = append(statements[vuln.ID], Statement{
			Affects:       affects,
			Status:        cdxStatus(analysis.State),
			Justification: string(analysis.Justification),
		})
	}
	return &CycloneDX{
		sbom:       sbom,
		statements: statements,
		logger:     log.WithPrefix("vex").With(log.String("format", "CycloneDX")),
	}
}

func (v *CycloneDX) NotAffected(vuln types.DetectedVulnerability, product, _ *core.Component) (types.ModifiedFinding, bool) {
	stmts, ok := v.statements[vuln.VulnerabilityID]
	if !ok {
		return types.ModifiedFinding{}, false
	}

	// Take the first statement that applies to the product in document order
	for _, stmt := range stmts {
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
	}
	return types.ModifiedFinding{}, false
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
