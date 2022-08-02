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
			// When cosign creates an attestation, it stores the predicate under a "Data" key.
			// https://github.com/sigstore/cosign/blob/938ad43f84aa183850014c8cc6d999f4b7ec5e8d/pkg/cosign/attestation/attestation.go#L39-L43
			data := attest.Predicate.(map[string]interface{})["Data"]
			switch data.(type) {
			case map[string]interface{}:
				return FormatAttestCycloneDXJSON, nil
			case string:
				return FormatAttestCycloneDXXML, nil
			}
		}
	}

	return FormatUnknown, nil
}
