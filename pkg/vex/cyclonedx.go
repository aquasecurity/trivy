package vex

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"go.uber.org/zap"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

type CycloneDX struct {
	sbom       *core.BOM
	statements []Statement
	logger     *zap.SugaredLogger
}

type Statement struct {
	VulnerabilityID string
	Affects         []string
	Status          types.FindingStatus
	Justification   string
}

func newCycloneDX(sbom *core.BOM, vex *cdx.BOM) *CycloneDX {
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
		sbom:       sbom,
		statements: stmts,
		logger:     log.Logger.With(zap.String("VEX format", "CycloneDX")),
	}
}

func (v *CycloneDX) Filter(result *types.Result, _ *core.BOM) {
	result.Vulnerabilities = lo.Filter(result.Vulnerabilities, func(vuln types.DetectedVulnerability, _ int) bool {
		stmt, ok := lo.Find(v.statements, func(item Statement) bool {
			return item.VulnerabilityID == vuln.VulnerabilityID
		})
		if !ok {
			return true
		}
		if !v.affected(vuln, stmt) {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(vuln, stmt.Status, stmt.Justification, "CycloneDX VEX"))
			return false
		}
		return true
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
			v.logger.Warnw("URN doesn't match with SBOM",
				zap.String("serial number", link.SerialNumber()),
				zap.Int("version", link.Version()))
			continue
		}
		if vuln.PkgIdentifier.Match(link.Reference()) && (stmt.Status == types.FindingStatusNotAffected || stmt.Status == types.FindingStatusFixed) {
			return false
		}
	}
	return true
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
