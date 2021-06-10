package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// JSONWriter implements result Writer
type JSONWriter struct {
	Output io.Writer
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(report Report) error {
	var v interface{} = report
	if os.Getenv("TRIVY_NEW_JSON_SCHEMA") == "" {
		// After migrating to the new JSON schema, TRIVY_NEW_JSON_SCHEMA will be removed.
		log.Logger.Warnf("DEPRECATED: the current JSON schema is deprecated, check %s for more information.",
			"https://github.com/aquasecurity/trivy/discussions/1050")
		v = report.Results
	}

	output, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprint(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}
	return nil
}
