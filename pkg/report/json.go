package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy/pkg/types"
)

// JSONWriter implements result Writer
type JSONWriter struct {
	Output io.Writer
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(ctx context.Context, report types.Report) error {
	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprintln(jw.Output, string(output)); err != nil {
		return fmt.Errorf("failed to write json: %w", err)
	}
	return nil
}
