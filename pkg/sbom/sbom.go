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

type Format string

const (
	FormatCycloneDXJSON              Format = "cyclonedx-json"
	FormatCycloneDXXML               Format = "cyclonedx-xml"
	FormatSPDXJSON                   Format = "spdx-json"
	FormatSPDXXML                    Format = "spdx-xml"
	FormatAttestCycloneDXJSON        Format = "attest-cyclonedx-json"
	FormatDecodedAttestCycloneDXJSON Format = "attest-decoded-cyclonedx-json"

	FormatUnknown Format = "unknown"
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

	// Try in-toto attestation
	e := attestation.Envelope{Payload: &in_toto.Statement{}}
	if err := json.NewDecoder(r).Decode(&e); err == nil {
		if s, ok := e.Payload.(*in_toto.Statement); ok {
			if s.PredicateType == in_toto.PredicateCycloneDX {
				return FormatAttestCycloneDXJSON, nil
			}
		}
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return FormatUnknown, xerrors.Errorf("seek error: %w", err)
	}

	// Try decoded in-toto statement
	var s in_toto.Statement
	if err := json.NewDecoder(r).Decode(&s); err == nil {
		if s.PredicateType == in_toto.PredicateCycloneDX {
			return FormatDecodedAttestCycloneDXJSON, nil
		}
	}

	return FormatUnknown, nil
}
