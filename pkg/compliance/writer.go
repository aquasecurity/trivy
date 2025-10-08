package compliance

import (
	"golang.org/x/xerrors"

	ctypes "github.com/aquasecurity/trivy/pkg/compliance/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	allReport     = "all"
	summaryReport = "summary"
)

// Writer defines the result write operation
type Writer interface {
	Write(ctypes.ComplianceReport) error
}

// Write writes the results in the given format
func Write(ctx context.Context, report *ctypes.ComplianceReport, option Option) error {
	switch option.Format {
	case types.FormatJSON:
		jwriter := JSONWriter{
			Output: option.Output,
			Report: option.Report,
		}
		return jwriter.Write(report)
	case types.FormatTable:
		if !report.empty() {
			complianceWriter := &TableWriter{
				Output:     option.Output,
				Report:     option.Report,
				Severities: option.Severities,
			}
			err := complianceWriter.Write(ctx, report)
			if err != nil {
				return err
			}
		}
		return nil
	default:
		return xerrors.Errorf(`unknown format %q. Use "json" or "table"`, option.Format)
	}
}
