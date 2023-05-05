package spdx

import (
	"io"

	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/tagvalue"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Writer struct {
	output    io.Writer
	version   string
	format    string
	marshaler *spdx.Marshaler
}

func NewWriter(output io.Writer, version string, spdxFormat string) Writer {
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
		if err := json.Write(spdxDoc, w.output); err != nil {
			return xerrors.Errorf("failed to save spdx json: %w", err)
		}
	} else {
		if err := tagvalue.Write(spdxDoc, w.output); err != nil {
			return xerrors.Errorf("failed to save spdx tag-value: %w", err)
		}
	}

	return nil
}
