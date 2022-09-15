package sbom

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/in-toto/in-toto-golang/in_toto"
	stypes "github.com/spdx/tools-golang/spdx"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type SBOM struct {
	OS           *types.OS
	Packages     []types.PackageInfo
	Applications []types.Application

	CycloneDX *types.CycloneDX
	SPDX      *stypes.Document2_2
}

type Format string

const (
	FormatCycloneDXJSON       Format = "cyclonedx-json"
	FormatCycloneDXXML        Format = "cyclonedx-xml"
	FormatSPDXJSON            Format = "spdx-json"
	FormatSPDXTV              Format = "spdx-tv"
	FormatSPDXXML             Format = "spdx-xml"
	FormatAttestCycloneDXJSON Format = "attest-cyclonedx-json"
	FormatUnknown             Format = "unknown"
)

var ErrUnknownFormat = xerrors.New("Unknown SBOM format")

func DetectFormat(r io.ReadSeeker) (Format, error) {
	type (
		cyclonedx struct {
			// XML specific field
			XMLNS string `json:"-" xml:"xmlns,attr"`

			// JSON specific field
			BOMFormat string `json:"bomFormat" xml:"-"`
		}

		spdx struct {
			SpdxID string `json:"SPDXID"`
		}
	)

	// Try CycloneDX JSON
	var cdxBom cyclonedx
	if err := json.NewDecoder(r).Decode(&cdxBom); err == nil {
		if cdxBom.BOMFormat == "CycloneDX" {
			return FormatCycloneDXJSON, nil
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return FormatUnknown, xerrors.Errorf("seek error: %w", err)
	}

	// Try CycloneDX XML
	if err := xml.NewDecoder(r).Decode(&cdxBom); err == nil {
		if strings.HasPrefix(cdxBom.XMLNS, "http://cyclonedx.org") {
			return FormatCycloneDXXML, nil
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return FormatUnknown, xerrors.Errorf("seek error: %w", err)
	}

	// Try SPDX json
	var spdxBom spdx
	if err := json.NewDecoder(r).Decode(&spdxBom); err == nil {
		if strings.HasPrefix(spdxBom.SpdxID, "SPDX") {
			return FormatSPDXJSON, nil
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return FormatUnknown, xerrors.Errorf("seek error: %w", err)
	}

	// Try SPDX tag-value
	if scanner := bufio.NewScanner(r); scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "SPDX") {
			return FormatSPDXTV, nil
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return FormatUnknown, xerrors.Errorf("seek error: %w", err)
	}

	// Try in-toto attestation
	var s attestation.Statement
	if err := json.NewDecoder(r).Decode(&s); err == nil {
		if s.PredicateType == in_toto.PredicateCycloneDX {
			return FormatAttestCycloneDXJSON, nil
		}
	}

	return FormatUnknown, nil
}
