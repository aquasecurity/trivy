package report

import (
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/xerrors"

	compliance "github.com/aquasecurity/trivy/pkg/compliance/types"
)

const (
	allReport     = "all"
	summaryReport = "summary"
)

type JSONWriter struct {
	Output io.Writer
	Report string
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(report *compliance.Report) error {
	var output []byte
	var err error

	var v any
	switch jw.Report {
	case allReport:
		v = report
	case summaryReport:
		v = BuildSummary(report)
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, jw.Report)
	}

	output, err = json.MarshalIndent(v, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprintln(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}

	return nil
}
