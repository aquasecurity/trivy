package vex

import (
	"encoding/json"
	"io"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/hashicorp/go-multierror"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VEX represents Vulnerability Exploitability eXchange. It abstracts multiple VEX formats.
// Note: This is in the experimental stage and does not yet support many specifications.
// The implementation may change significantly.
type VEX interface {
	Filter([]types.DetectedVulnerability) []types.DetectedVulnerability
}

type Statement struct {
	VulnerabilityID string
	Affects         []string
	Status          Status
	Justification   string // TODO: define a type
}

type OpenVEX struct {
	vex    openvex.VEX
	logger *zap.SugaredLogger
}

func newOpenVEX(vex openvex.VEX) VEX {
	logger := log.Logger.With(zap.String("VEX format", "OpenVEX"))

	return &OpenVEX{
		vex:    vex,
		logger: logger,
	}
}

func (v *OpenVEX) Filter(vulns []types.DetectedVulnerability) []types.DetectedVulnerability {
	return lo.Filter(vulns, func(vuln types.DetectedVulnerability, _ int) bool {
		stmts := v.vex.Matches(vuln.VulnerabilityID, vuln.PkgRef, nil)
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

type CycloneDX struct {
	sbom       *ftypes.CycloneDX
	statements []Statement
	logger     *zap.SugaredLogger
}

func newCycloneDX(sbom *ftypes.CycloneDX, vex *cdx.BOM) *CycloneDX {
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
		if vuln.PkgRef == link.Reference() &&
			(stmt.Status == StatusNotAffected || stmt.Status == StatusFixed) {
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
	} else {
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
	if report.CycloneDX == nil {
		return nil, xerrors.New("CycloneDX VEX can be used with CycloneDX SBOM")
	}
	return newCycloneDX(report.CycloneDX, vex), nil
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
