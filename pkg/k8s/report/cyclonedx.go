package report

import (
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx/core"
)

// CycloneDXWriter implements types.Writer
type CycloneDXWriter struct {
	encoder   cdx.BOMEncoder
	marshaler *core.CycloneDX
}

func NewCycloneDXWriter(output io.Writer, format cdx.BOMFileFormat, appVersion string, opts ...core.Option) CycloneDXWriter {
	encoder := cdx.NewBOMEncoder(output, format)
	encoder.SetPretty(true)
	return CycloneDXWriter{
		encoder:   encoder,
		marshaler: core.NewCycloneDX(appVersion, opts...),
	}
}

func (w CycloneDXWriter) Write(component *core.Component) error {
	bom := w.marshaler.Marshal(component)
	return w.encoder.Encode(bom)
}
