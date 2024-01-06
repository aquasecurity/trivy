package vex

import (
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"go.uber.org/zap"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type OpenVEX struct {
	vex    openvex.VEX
	logger *zap.SugaredLogger
}

func newOpenVEX(vex openvex.VEX) VEX {
	return &OpenVEX{
		vex:    vex,
		logger: log.Logger.With(zap.String("VEX format", "OpenVEX")),
	}
}

func (v *OpenVEX) Filter(vulns []types.DetectedVulnerability) []types.DetectedVulnerability {
	return lo.Filter(vulns, func(vuln types.DetectedVulnerability, _ int) bool {
		var stmts []openvex.Statement
		if vuln.PkgIdentifier.PURL != nil {
			matchedStmts := v.vex.Matches(vuln.VulnerabilityID, vuln.PkgIdentifier.PURL.String(), nil)
			stmts = append(stmts, matchedStmts...)
		}
		if len(stmts) == 0 {
			return true
		}

		// Take the latest statement for a given vulnerability and product
		// as a sequence of statements can be overridden by the newer one.
		// cf. https://github.com/openvex/spec/blob/fa5ba0c0afedb008dc5ebad418548cacf16a3ca7/OPENVEX-SPEC.md#the-vex-statement
		stmt := stmts[len(stmts)-1]
		if stmt.Status == openvex.StatusNotAffected || stmt.Status == openvex.StatusFixed {
			v.logger.Infow("Filtered out the detected vulnerability", zap.String("vulnerability-id", vuln.VulnerabilityID),
				zap.String("status", string(stmt.Status)), zap.String("justification", string(stmt.Justification)))
			return false
		}
		return true
	})
}
