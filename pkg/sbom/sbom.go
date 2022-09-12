package sbom

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type SBOM struct {
	OS           *types.OS
	Packages     []types.PackageInfo
	Applications []types.Application

	CycloneDX *types.CycloneDX
	SPDX      *types.SPDX
}

type Unmarshaler interface {
	Unmarshal(io.Reader) (SBOM, error)
}

type Format string

const (
	FormatCycloneDXJSON = "cyclonedx-json"
	FormatCycloneDXXML  = "cyclonedx-xml"
	FormatSPDXJSON      = "spdx-json"
	FormatSPDXTV        = "spdx-tv"
	FormatUnknown       = "unknown"
)

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
	return FormatUnknown, nil
}
