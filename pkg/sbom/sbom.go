package sbom

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
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

type cdxHeader struct {
	// XML specific field
	XMLNS string `json:"-" xml:"xmlns,attr"`

	// JSON specific field
	BOMFormat string `json:"bomFormat" xml:"-"`
}

type spdxHeader struct {
	SpdxID string `json:"SPDXID"`
}

func IsCycloneDXJSON(r io.ReadSeeker) (bool, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return false, xerrors.Errorf("seek error: %w", err)
	}

	var cdxBom cdxHeader
	if err := json.NewDecoder(r).Decode(&cdxBom); err == nil {
		if cdxBom.BOMFormat == "CycloneDX" {
			return true, nil
		}
	}
	return false, nil
}
func IsCycloneDXXML(r io.ReadSeeker) (bool, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return false, xerrors.Errorf("seek error: %w", err)
	}

	var cdxBom cdxHeader
	if err := xml.NewDecoder(r).Decode(&cdxBom); err == nil {
		if strings.HasPrefix(cdxBom.XMLNS, "http://cyclonedx.org") {
			return true, nil
		}
	}
	return false, nil
}

func IsSPDXJSON(r io.ReadSeeker) (bool, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return false, xerrors.Errorf("seek error: %w", err)
	}

	var spdxBom spdxHeader
	if err := json.NewDecoder(r).Decode(&spdxBom); err == nil {
		if strings.HasPrefix(spdxBom.SpdxID, "SPDX") {
			return true, nil
		}
	}
	return false, nil
}

func IsSPDXTV(r io.ReadSeeker) (bool, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return false, xerrors.Errorf("seek error: %w", err)
	}

	if scanner := bufio.NewScanner(r); scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "SPDX") {
			return true, nil
		}
	}
	return false, nil
}

func DetectFormat(r io.ReadSeeker) (Format, error) {
	// Rewind the SBOM file at the end
	defer r.Seek(0, io.SeekStart)

	// Try CycloneDX JSON
	if ok, err := IsCycloneDXJSON(r); err != nil {
		return FormatUnknown, err
	} else if ok {
		return FormatCycloneDXJSON, nil
	}

	// Try CycloneDX XML
	if ok, err := IsCycloneDXXML(r); err != nil {
		return FormatUnknown, err
	} else if ok {
		return FormatCycloneDXXML, nil
	}

	// Try SPDX json
	if ok, err := IsSPDXJSON(r); err != nil {
		return FormatUnknown, err
	} else if ok {
		return FormatSPDXJSON, nil
	}

	// Try SPDX tag-value
	if ok, err := IsSPDXTV(r); err != nil {
		return FormatUnknown, err
	} else if ok {
		return FormatSPDXTV, nil
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

	m, ok := s.Predicate.(map[string]any)
	if !ok {
		return "", false
	}

	if _, ok := m["Data"]; ok {
		return FormatLegacyCosignAttestCycloneDXJSON, true
	}

	return FormatAttestCycloneDXJSON, true
}

func Decode(ctx context.Context, f io.Reader, format Format) (types.SBOM, error) {
	var (
		v       any
		bom     *core.BOM
		decoder interface{ Decode(any) error }
	)

	switch format {
	case FormatCycloneDXJSON:
		bom = core.NewBOM(core.Options{GenerateBOMRef: true})
		v = &cyclonedx.BOM{BOM: bom}
		decoder = json.NewDecoder(f)
	case FormatAttestCycloneDXJSON:
		// dsse envelope
		//   => in-toto attestation
		//     => CycloneDX JSON
		bom = core.NewBOM(core.Options{GenerateBOMRef: true})
		v = &attestation.Statement{
			Predicate: &cyclonedx.BOM{BOM: bom},
		}
		decoder = json.NewDecoder(f)
	case FormatLegacyCosignAttestCycloneDXJSON:
		// dsse envelope
		//   => in-toto attestation
		//     => cosign predicate
		//       => CycloneDX JSON
		bom = core.NewBOM(core.Options{GenerateBOMRef: true})
		v = &attestation.Statement{
			Predicate: &attestation.CosignPredicate{
				Data: &cyclonedx.BOM{BOM: bom},
			},
		}
		decoder = json.NewDecoder(f)
	case FormatSPDXJSON:
		bom = core.NewBOM(core.Options{})
		v = &spdx.SPDX{BOM: bom}
		decoder = json.NewDecoder(f)
	case FormatSPDXTV:
		bom = core.NewBOM(core.Options{})
		v = &spdx.SPDX{BOM: bom}
		decoder = spdx.NewTVDecoder(f)
	default:
		return types.SBOM{}, xerrors.Errorf("%s scanning is not yet supported", format)

	}

	// Decode a file content into core.BOM
	if err := decoder.Decode(v); err != nil {
		return types.SBOM{}, xerrors.Errorf("failed to decode: %w", err)
	}

	var sbom types.SBOM
	if err := sbomio.NewDecoder(bom).Decode(ctx, &sbom); err != nil {
		return types.SBOM{}, xerrors.Errorf("failed to decode: %w", err)
	}

	return sbom, nil
}
