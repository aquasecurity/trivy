package vex

import (
	"context"
	"fmt"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex/oci"
)

type OpenVEX struct {
	vex    openvex.VEX
	source string
}

// NewOCI discovers and loads the OpenVEX document attached to the scanned OCI
// image. It returns nil when the report is not an OCI image or no VEX
// attestation is found.
func NewOCI(ctx context.Context, report *types.Report) (*OpenVEX, error) {
	if report.ArtifactType != ftypes.TypeContainerImage || len(report.Metadata.RepoDigests) == 0 {
		return nil, xerrors.New("'--vex oci' can be used only when scanning OCI artifacts stored in registries")
	}

	// TODO(knqyf263): Add the PURL field to Report.Metadata
	p, err := purl.New(purl.TypeOCI, report.Metadata, ftypes.Package{})
	if err != nil {
		return nil, xerrors.Errorf("failed to create a package URL: %w", err)
	}

	// TODO(#8916): thread the caller's RegistryOptions through so registry
	// credentials, --insecure and TLS settings reach the attestation fetch
	// instead of using an empty config.
	doc, err := oci.Discover(ctx, p, ftypes.RegistryOptions{})
	if err != nil {
		return nil, xerrors.Errorf("failed to retrieve VEX attestation: %w", err)
	}
	if doc == nil {
		return nil, nil
	}
	return newOpenVEX(*doc, fmt.Sprintf("VEX attestation in OCI registry (%s)", p.String())), nil
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
