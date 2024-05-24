package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

// JSONWriter implements result Writer
type JSONWriter struct {
	Output      io.Writer
	ListAllPkgs bool
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(_ context.Context, report types.Report) error {
	if !jw.ListAllPkgs {
		// Delete packages
		for i := range report.Results {
			report.Results[i].Packages = nil
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
