package report

import (
	"context"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
)

// CycloneDXWriter implements types.Writer
type CycloneDXWriter struct {
	encoder   cdx.BOMEncoder
	marshaler cyclonedx.Marshaler
}

// NewCycloneDXWriter constract new CycloneDXWriter
func NewCycloneDXWriter(output io.Writer, format cdx.BOMFileFormat, appVersion string) CycloneDXWriter {
	encoder := cdx.NewBOMEncoder(output, format)
	encoder.SetPretty(true)
	encoder.SetEscapeHTML(false)
	return CycloneDXWriter{
		encoder:   encoder,
		marshaler: cyclonedx.NewMarshaler(appVersion),
	}
}

func (w CycloneDXWriter) Write(ctx context.Context, component *core.BOM) error {
	bom, err := w.marshaler.Marshal(ctx, component)
	if err != nil {
		return xerrors.Errorf("CycloneDX marshal error: %w", err)
	}
	return w.encoder.Encode(bom)
}
