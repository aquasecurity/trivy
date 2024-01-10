package vex

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"go.uber.org/zap"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type CycloneDX struct {
	sbom       *ftypes.CycloneDX
	statements []Statement
	logger     *zap.SugaredLogger
}

type Statement struct {
	VulnerabilityID string
	Affects         []string
	Status          Status
	Justification   string // TODO: define a type
}

func newCycloneDX(cdxSBOM *ftypes.CycloneDX, vex *cdx.BOM) *CycloneDX {
	var stmts []Statement
	for _, vuln := range lo.FromPtr(vex.Vulnerabilities) {
		affects := lo.Map(lo.FromPtr(vuln.Affects), func(item cdx.Affects, index int) string {
			return item.Ref
		})

		analysis := lo.FromPtr(vuln.Analysis)
		stmts = append(stmts, Statement{
			VulnerabilityID: vuln.ID,
			Affects:         affects,
			Status:          cdxStatus(analysis.State),
			Justification:   string(analysis.Justification),
		})
	}
	return &CycloneDX{
		sbom:       cdxSBOM,
		statements: stmts,
		logger:     log.Logger.With(zap.String("VEX format", "CycloneDX")),
	}
}

func (v *CycloneDX) Filter(vulns []types.DetectedVulnerability) []types.DetectedVulnerability {
	return lo.Filter(vulns, func(vuln types.DetectedVulnerability, _ int) bool {
		stmt, ok := lo.Find(v.statements, func(item Statement) bool {
			return item.VulnerabilityID == vuln.VulnerabilityID
		})
		if !ok {
			return true
		}
		return v.affected(vuln, stmt)
	})
}

func (v *CycloneDX) affected(vuln types.DetectedVulnerability, stmt Statement) bool {
	for _, affect := range stmt.Affects {
		// Affect must be BOM-Link at the moment
		link, err := cdx.ParseBOMLink(affect)
		if err != nil {
			v.logger.Warnw("Unable to parse BOM-Link", zap.String("affect", affect))
			continue
		}
		if v.sbom.SerialNumber != link.SerialNumber() || v.sbom.Version != link.Version() {
			v.logger.Warnw("URN doesn't match with SBOM", zap.String("serial number", link.SerialNumber()),
				zap.Int("version", link.Version()))
			continue
		}
		if vuln.PkgIdentifier.Match(link.Reference()) && (stmt.Status == StatusNotAffected || stmt.Status == StatusFixed) {
			v.logger.Infow("Filtered out the detected vulnerability", zap.String("vulnerability-id", vuln.VulnerabilityID),
				zap.String("status", string(stmt.Status)), zap.String("justification", stmt.Justification))
			return false
		}
	}
	return true
}

func cdxStatus(s cdx.ImpactAnalysisState) Status {
	switch s {
	case cdx.IASResolved, cdx.IASResolvedWithPedigree:
		return StatusFixed
	case cdx.IASExploitable:
		return StatusAffected
	case cdx.IASInTriage:
		return StatusUnderInvestigation
	case cdx.IASFalsePositive, cdx.IASNotAffected:
		return StatusNotAffected
	}
	return StatusUnknown
}
