package spdx

import (
	"encoding/json"
	"io"

	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/tagvalue"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Writer struct {
	output    io.Writer
	version   string
	format    types.Format
	marshaler *spdx.Marshaler
}

func NewWriter(output io.Writer, version string, spdxFormat types.Format) Writer {
	return Writer{
		output:    output,
		version:   version,
		format:    spdxFormat,
		marshaler: spdx.NewMarshaler(version),
	}
}

func (w Writer) Write(report types.Report) error {
	spdxDoc, err := w.marshaler.Marshal(report)
	if err != nil {
		return xerrors.Errorf("failed to marshal spdx: %w", err)
	}

	if w.format == "spdx-json" {
		if err := writeSPDXJson(spdxDoc, w.output); err != nil {
			return xerrors.Errorf("failed to save spdx json: %w", err)
		}
	} else {
		if err := tagvalue.Write(spdxDoc, w.output); err != nil {
			return xerrors.Errorf("failed to save spdx tag-value: %w", err)
		}
	}

	return nil
}

// writeSPDXJson writes in human-readable format(multiple lines)
// use function from `github.com/spdx/tools-golang` after release https://github.com/spdx/tools-golang/pull/213
func writeSPDXJson(doc *v2_3.Document, w io.Writer) error {
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	return nil
}
