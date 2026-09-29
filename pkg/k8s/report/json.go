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
	case AllReport:
		output, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			return xerrors.Errorf("failed to write json: %w", err)
		}
	case SummaryReport:
		output, err = json.MarshalIndent(report.consolidate(), "", "  ")
		if err != nil {
			return xerrors.Errorf("failed to write json: %w", err)
		}
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, jw.Report)
	}
	if _, err = fmt.Fprintln(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}

	return nil
}
