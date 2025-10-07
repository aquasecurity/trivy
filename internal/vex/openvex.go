package vex

import (
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

type OpenVEX struct {
	vex    openvex.VEX
	source string
}

func newOpenVEX(vex openvex.VEX, source string) *OpenVEX {
	return &OpenVEX{
		vex:    vex,
		source: source,
	}
}

func (v *OpenVEX) Filter(result *types.Result, bom *core.BOM) {
	filterVulnerabilities(result, bom, v.NotAffected)
}

func (v *OpenVEX) NotAffected(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool) {
	stmts := v.Matches(vuln, product, subComponent)
	if len(stmts) == 0 {
		return types.ModifiedFinding{}, false
	}

	// Take the latest statement for a given vulnerability and product
	// as a sequence of statements can be overridden by the newer one.
	// cf. https://github.com/openvex/spec/blob/fa5ba0c0afedb008dc5ebad418548cacf16a3ca7/OPENVEX-SPEC.md#the-vex-statement
	stmt := stmts[len(stmts)-1]
	if stmt.Status == openvex.StatusNotAffected || stmt.Status == openvex.StatusFixed {
		modifiedFindings := types.NewModifiedFinding(vuln, findingStatus(stmt.Status), string(stmt.Justification), v.source)
		return modifiedFindings, true
	}
	return types.ModifiedFinding{}, false
}

func (v *OpenVEX) Matches(vuln types.DetectedVulnerability, product, subComponent *core.Component) []openvex.Statement {
	if product == nil || product.PkgIdentifier.PURL == nil {
		return nil
	}

	var subComponentPURL string
	if subComponent != nil && subComponent.PkgIdentifier.PURL != nil {
		subComponentPURL = subComponent.PkgIdentifier.PURL.String()
	}
	return v.vex.Matches(vuln.VulnerabilityID, product.PkgIdentifier.PURL.String(), []string{subComponentPURL})
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
