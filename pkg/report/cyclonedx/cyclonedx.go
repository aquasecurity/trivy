package cyclonedx

import (
	"context"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Writer implements types.Writer
type Writer struct {
	output    io.Writer
	format    cdx.BOMFileFormat
	marshaler cyclonedx.Marshaler
}

func NewWriter(output io.Writer, appVersion string) Writer {
	return Writer{
		output:    output,
		format:    cdx.BOMFileFormatJSON,
		marshaler: cyclonedx.NewMarshaler(appVersion),
	}
}

// Write writes the results in CycloneDX format
func (w Writer) Write(ctx context.Context, report types.Report) error {
	bom, err := w.marshaler.MarshalReport(ctx, report)
	if err != nil {
		return fmt.Errorf("CycloneDX marshal error: %w", err)
	}

	encoder := cdx.NewBOMEncoder(w.output, w.format)
	encoder.SetPretty(true)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(bom); err != nil {
		return fmt.Errorf("failed to encode bom: %w", err)
	}

	return nil
}
