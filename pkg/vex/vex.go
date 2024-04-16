package vex

import (
	"encoding/json"
	"io"
	"os"

	csaf "github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/hashicorp/go-multierror"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VEX represents Vulnerability Exploitability eXchange. It abstracts multiple VEX formats.
// Note: This is in the experimental stage and does not yet support many specifications.
// The implementation may change significantly.
type VEX interface {
	Filter(*types.Result, *core.BOM)
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
	} else if v != nil {
		return v, nil
	}

	// Try CSAF
	if v, err := decodeCSAF(f); err != nil {
		errs = multierror.Append(errs, err)
	} else if v != nil {
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
	if report.ArtifactType != ftypes.ArtifactCycloneDX {
		return nil, xerrors.New("CycloneDX VEX can be used with CycloneDX SBOM")
	}
	return newCycloneDX(report.BOM, vex), nil
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

func decodeCSAF(r io.ReadSeeker) (VEX, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}
	var adv csaf.Advisory
	if err := json.NewDecoder(r).Decode(&adv); err != nil {
		return nil, err
	}
	if adv.Vulnerabilities == nil {
		return nil, nil
	}
	return newCSAF(adv), nil
}
