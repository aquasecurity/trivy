package sbom

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Format string

const (
	FormatCycloneDXJSON       Format = "cyclonedx-json"
	FormatCycloneDXXML        Format = "cyclonedx-xml"
	FormatSPDXJSON            Format = "spdx-json"
	FormatSPDXTV              Format = "spdx-tv"
	FormatSPDXXML             Format = "spdx-xml"
	FormatAttestCycloneDXJSON Format = "attest-cyclonedx-json"
	FormatUnknown             Format = "unknown"

	// FormatLegacyCosignAttestCycloneDXJSON is used to support the older format of CycloneDX JSON Attestation
	// produced by the Cosign V1.
	// ref. https://github.com/sigstore/cosign/pull/2718
	FormatLegacyCosignAttestCycloneDXJSON Format = "legacy-cosign-attest-cyclonedx-json"

	// PredicateCycloneDXBeforeV05 is the PredicateCycloneDX value defined in in-toto-golang before v0.5.0.
	// This is necessary for backward-compatible SBOM detection.
	// ref. https://github.com/in-toto/in-toto-golang/pull/188
	PredicateCycloneDXBeforeV05 = "https://cyclonedx.org/schema"
)

var ErrUnknownFormat = xerrors.New("Unknown SBOM format")

func DetectFormat(r io.ReadSeeker) (Format, error) {
	// Rewind the SBOM file at the end
	defer r.Seek(0, io.SeekStart)

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
	format, ok := decodeAttestCycloneDXJSONFormat(r)
	if ok {
		return format, nil
	}

	return FormatUnknown, nil
}

func decodeAttestCycloneDXJSONFormat(r io.ReadSeeker) (Format, bool) {
	var s attestation.Statement

	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return "", false
	}

	if s.PredicateType != in_toto.PredicateCycloneDX && s.PredicateType != PredicateCycloneDXBeforeV05 {
		return "", false
	}

	if s.Predicate == nil {
		return "", false
	}

	m, ok := s.Predicate.(map[string]interface{})
	if !ok {
		return "", false
	}

	if _, ok := m["Data"]; ok {
		return FormatLegacyCosignAttestCycloneDXJSON, true
	}

	return FormatAttestCycloneDXJSON, true
}

func Decode(f io.Reader, format Format) (types.SBOM, error) {
	var (
		v       interface{}
		bom     types.SBOM
		decoder interface{ Decode(any) error }
	)

	switch format {
	case FormatCycloneDXJSON:
		v = &cyclonedx.CycloneDX{SBOM: &bom}
		decoder = json.NewDecoder(f)
	case FormatAttestCycloneDXJSON:
		// dsse envelope
		//   => in-toto attestation
		//     => CycloneDX JSON
		v = &attestation.Statement{
			Predicate: &cyclonedx.CycloneDX{SBOM: &bom},
		}
		decoder = json.NewDecoder(f)
	case FormatLegacyCosignAttestCycloneDXJSON:
		// dsse envelope
		//   => in-toto attestation
		//     => cosign predicate
		//       => CycloneDX JSON
		v = &attestation.Statement{
			Predicate: &attestation.CosignPredicate{
				Data: &cyclonedx.CycloneDX{SBOM: &bom},
			},
		}
		decoder = json.NewDecoder(f)
	case FormatSPDXJSON:
		v = &spdx.SPDX{SBOM: &bom}
		decoder = json.NewDecoder(f)
	case FormatSPDXTV:
		v = &spdx.SPDX{SBOM: &bom}
		decoder = spdx.NewTVDecoder(f)

	default:
		return types.SBOM{}, xerrors.Errorf("%s scanning is not yet supported", format)

	}

	// Decode a file content into sbom.SBOM
	if err := decoder.Decode(v); err != nil {
		return types.SBOM{}, xerrors.Errorf("failed to decode: %w", err)
	}

	return bom, nil
}
