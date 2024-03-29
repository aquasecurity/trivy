package vex

import (
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

type OpenVEX struct {
	vex openvex.VEX
}

func newOpenVEX(vex openvex.VEX) VEX {
	return &OpenVEX{
		vex: vex,
	}
}

func (v *OpenVEX) Filter(result *types.Result, bom *core.BOM) {
	result.Vulnerabilities = lo.Filter(result.Vulnerabilities, func(vuln types.DetectedVulnerability, _ int) bool {
		if vuln.PkgIdentifier.PURL == nil {
			return true
		}

		stmts := v.Matches(vuln, bom)
		if len(stmts) == 0 {
			return true
		}

		// Take the latest statement for a given vulnerability and product
		// as a sequence of statements can be overridden by the newer one.
		// cf. https://github.com/openvex/spec/blob/fa5ba0c0afedb008dc5ebad418548cacf16a3ca7/OPENVEX-SPEC.md#the-vex-statement
		stmt := stmts[len(stmts)-1]
		if stmt.Status == openvex.StatusNotAffected || stmt.Status == openvex.StatusFixed {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(vuln, findingStatus(stmt.Status), string(stmt.Justification), "OpenVEX"))
			return false
		}
		return true
	})
}

func (v *OpenVEX) Matches(vuln types.DetectedVulnerability, bom *core.BOM) []openvex.Statement {
	root := bom.Root()
	if root != nil && root.PkgID.PURL != nil {
		stmts := v.vex.Matches(vuln.VulnerabilityID, root.PkgID.PURL.String(), []string{vuln.PkgIdentifier.PURL.String()})
		if len(stmts) != 0 {
			return stmts
		}
	}
	return v.vex.Matches(vuln.VulnerabilityID, vuln.PkgIdentifier.PURL.String(), nil)
}

func findingStatus(status openvex.Status) types.FindingStatus {
	switch status {
	case openvex.StatusNotAffected:
		return types.FindingStatusNotAffected
	case openvex.StatusFixed:
		return types.FindingStatusFixed
	case openvex.StatusUnderInvestigation:
		return types.FindingStatusUnderInvestigation
	default:
		return types.FindingStatusUnknown
	}
}
