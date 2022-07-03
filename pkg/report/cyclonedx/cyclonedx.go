package cyclonedx

import (
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Writer implements types.Writer
type Writer struct {
	output    io.Writer
	format    cdx.BOMFileFormat
	marshaler *cyclonedx.Marshaler
}

func NewWriter(output io.Writer, appVersion string) Writer {
	return Writer{
		output:    output,
		format:    cdx.BOMFileFormatJSON,
		marshaler: cyclonedx.NewMarshaler(appVersion),
	}
}

// Write writes the results in CycloneDX format
func (w Writer) Write(report types.Report) error {
	var bom *cdx.BOM
	var err error

	// When the input is CycloneDX, only vulnerabilities will be stored in CycloneDX.
	// Each vulnerability has a reference to a component in the original CycloneDX.
	// e.g. "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#jackson-databind-2.8.0"
	if report.ArtifactType == ftypes.ArtifactCycloneDX {
		log.Logger.Info("Components will not be exported in the CycloneDX report as the input is CycloneDX")
		bom, err = w.marshaler.MarshalVulnerabilities(report)
	} else {
		bom, err = w.marshaler.Marshal(report)
	}
	if err != nil {
		return xerrors.Errorf("CycloneDX marshal error: %w", err)
	}

	encoder := cdx.NewBOMEncoder(w.output, w.format)
	encoder.SetPretty(true)
	if err = encoder.Encode(bom); err != nil {
		return xerrors.Errorf("failed to encode bom: %w", err)
	}

	return nil
}
