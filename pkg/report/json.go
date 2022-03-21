package report

import (
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

// JSONWriter implements result Writer
type JSONWriter struct {
	Output io.Writer
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(report types.Report) error {
	for i := 0; i < len(report.Results); i++ {
		for j := 0; j < len(report.Results[i].Vulnerabilities); j++ {
			report.Results[i].Vulnerabilities[j].VendorSeverity = nil
		}
	}

	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprintln(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}
	return nil
}
