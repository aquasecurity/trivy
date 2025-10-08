package compliance

import (
	"context"

	"golang.org/x/xerrors"

	creport "github.com/aquasecurity/trivy/internal/compliance/report"
	ctypes "github.com/aquasecurity/trivy/pkg/compliance/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Writer defines the result write operation
type Writer interface {
	Write(ctypes.Report) error
}

// Write writes the results in the given format
func Write(ctx context.Context, report *ctypes.Report, option Option) error {
	switch option.Format {
	case types.FormatJSON:
		jwriter := creport.JSONWriter{
			Output: option.Output,
			Report: option.Report,
		}
		return jwriter.Write(report)
	case types.FormatTable:
		if !report.Empty() {
			complianceWriter := &creport.TableWriter{
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
