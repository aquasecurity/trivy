package report

import (
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/xerrors"
)

type JSONWriter struct {
	Output io.Writer
	Report string
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(report Report) error {
	var output []byte
	var err error

	switch jw.Report {
	case allReport:
		output, err = json.MarshalIndent(report, "", "  ")
	case summaryReport:
		output, err = json.MarshalIndent(report.consolidate(), "", "  ")
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, jw.Report)
	}

	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprintln(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}

	return nil
}
