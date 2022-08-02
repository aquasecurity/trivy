package sbom

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type SBOM struct {
	OS           *types.OS
	Packages     []types.PackageInfo
	Applications []types.Application

	CycloneDX *types.CycloneDX
}

type Unmarshaler interface {
	Unmarshal(io.Reader) (SBOM, error)
}

type Format string

const (
	FormatCycloneDXJSON       = "cyclonedx-json"
	FormatCycloneDXXML        = "cyclonedx-xml"
	FormatSPDXJSON            = "spdx-json"
	FormatSPDXXML             = "spdx-xml"
	FormatAttestCycloneDXJSON = "attest-cyclonedx-json"
	FormatAttestCycloneDXXML  = "attest-cyclonedx-xml"
	FormatUnknown             = "unknown"
)

func DetectFormat(r io.ReadSeeker) (Format, error) {
	type cyclonedx struct {
		// XML specific field
		XMLNS string `json:"-" xml:"xmlns,attr"`

		// JSON specific field
		BOMFormat string `json:"bomFormat" xml:"-"`
	}

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

	// TODO: implement SPDX

	// Try Attestation
	if attest, err := attestation.Decode(r); err == nil {
		if attest.PredicateType == in_toto.PredicateCycloneDX {
			switch attest.Predicate.(type) {
			case map[string]interface{}:
				return FormatAttestCycloneDXJSON, nil

				// cosign command cannot create an attestation from xml format
				//case string:
				//	return FormatAttestCycloneDXXML, nil
			}
		}
	}

	return FormatUnknown, nil
}
