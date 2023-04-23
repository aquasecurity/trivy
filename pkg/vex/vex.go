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
	"golang.org/x/exp/slices"
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
	statements []Statement
	logger     *zap.SugaredLogger
}

func newOpenVEX(cycloneDX *ftypes.CycloneDX, vex openvex.VEX) VEX {
	logger := log.Logger.With(zap.String("VEX format", "OpenVEX"))

	openvex.SortStatements(vex.Statements, lo.FromPtr(vex.Timestamp))

	// Convert openvex.Statement to Statement
	stmts := lo.Map(vex.Statements, func(stmt openvex.Statement, index int) Statement {
		return Statement{
			// TODO: add subcomponents, etc.
			VulnerabilityID: stmt.Vulnerability,
			Affects:         stmt.Products,
			Status:          Status(stmt.Status),
			Justification:   string(stmt.Justification),
		}
	})
	// Reverse sorted statements so that the latest statement can come first.
	stmts = lo.Reverse(stmts)

	// If the SBOM format referenced by OpenVEX is CycloneDX
	if cycloneDX != nil {
		return &CycloneDX{
			sbom:       cycloneDX,
			statements: stmts,
			logger:     logger,
		}
	}
	return &OpenVEX{
		statements: stmts,
		logger:     logger,
	}
}

func (v *OpenVEX) Filter(vulns []types.DetectedVulnerability) []types.DetectedVulnerability {
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

func (v *OpenVEX) affected(vuln types.DetectedVulnerability, stmt Statement) bool {
	if slices.Contains(stmt.Affects, vuln.PkgRef) &&
		(stmt.Status == StatusNotAffected || stmt.Status == StatusFixed) {
		v.logger.Infow("Filtered out the detected vulnerability", zap.String("vulnerability-id", vuln.VulnerabilityID),
			zap.String("status", string(stmt.Status)), zap.String("justification", stmt.Justification))
		return false
	}
	return true
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
	if v, err := decodeOpenVEX(f, report); err != nil {
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

func decodeOpenVEX(r io.ReadSeeker, report types.Report) (VEX, error) {
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
	return newOpenVEX(report.CycloneDX, openVEX), nil
}
