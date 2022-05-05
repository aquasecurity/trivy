package k8s

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

type JSONWriter struct {
	Output io.Writer
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(report types.K8sReport) error {
	// VendorSeverity includes all vendor severities.
	// It would be noisy to users, so it should be removed from the JSON output.
	for _, r := range report.Resources {
		for i := 0; i < len(r.Results); i++ {
			for j := 0; j < len(r.Results[i].Vulnerabilities); j++ {
				r.Results[i].Vulnerabilities[j].VendorSeverity = nil
			}
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
