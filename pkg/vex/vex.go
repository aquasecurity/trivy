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
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
)

// VEX represents Vulnerability Exploitability eXchange. It abstracts multiple VEX formats.
// Note: This is in the experimental stage and does not yet support many specifications.
// The implementation may change significantly.
type VEX interface {
	Statement(vulnID string) Statement
}

type Statement struct {
	VulnerabilityID string
	Affects         []string
	Status          Status
	Justification   string // TODO: define a type
}

type OpenVEX struct {
	*openvex.VEX
}

func (v *OpenVEX) Statement(vulnID string) Statement {
	stmt := v.StatementFromID(vulnID)
	if stmt == nil {
		return Statement{}
	}
	return Statement{
		// TODO: add subcomponents, etc.
		VulnerabilityID: stmt.Vulnerability,
		Affects:         stmt.Products,
		Status:          Status(stmt.Status),
		Justification:   string(stmt.Justification),
	}
}

type CycloneDX struct {
	*cdx.BOM
}

func (v *CycloneDX) Statement(vulnID string) Statement {
	vuln, ok := lo.Find(lo.FromPtr(v.Vulnerabilities), func(vuln cdx.Vulnerability) bool {
		return vuln.ID == vulnID
	})
	if !ok {
		return Statement{}
	}

	affects := lo.Map(lo.FromPtr(vuln.Affects), func(item cdx.Affects, index int) string {
		return item.Ref
	})

	analysis := lo.FromPtr(vuln.Analysis)

	return Statement{
		VulnerabilityID: vuln.ID,
		Affects:         affects,
		Status:          v.status(analysis.State),
		Justification:   string(analysis.Justification),
	}
}

func (v *CycloneDX) status(s cdx.ImpactAnalysisState) Status {
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

func Open(filePath string) (VEX, error) {
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
		return decodeCycloneDXJSON(f)
	}

	// Try OpenVEX
	if v, err := decodeOpenVEX(f); err != nil {
		errs = multierror.Append(errs, err)
	} else if v.Context != "" {
		return v, nil
	}

	return nil, xerrors.Errorf("unable to load VEX: %w", errs)
}

func decodeCycloneDXJSON(r io.ReadSeeker) (*CycloneDX, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}
	bom, err := cyclonedx.DecodeJSON(r)
	if err != nil {
		return nil, xerrors.Errorf("json decode error: %w", err)
	}
	return &CycloneDX{BOM: bom}, nil
}

func decodeOpenVEX(r io.ReadSeeker) (*OpenVEX, error) {
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
	return &OpenVEX{VEX: &openVEX}, nil
}
