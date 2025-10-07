package report

import (
	"context"
	"io"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	pkgReport "github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

type TableWriter struct {
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
}

const (
	ControlIDColumn   = "ID"
	SeverityColumn    = "Severity"
	ControlNameColumn = "Control Name"
	StatusColumn      = "Status"
	IssuesColumn      = "Issues"
)

func (tw TableWriter) Write(ctx context.Context, report *ComplianceReport) error {
	switch tw.Report {
	case allReport:
		t := pkgReport.NewWriter(pkgReport.Options{
			Output:     tw.Output,
			Severities: tw.Severities,
		})
		for _, cr := range report.Results {
			r := types.Report{Results: cr.Results}
			err := t.Write(ctx, r)
			if err != nil {
				return err
			}
		}
	case summaryReport:
		writer := NewSummaryWriter(tw.Output)
		return writer.Write(report)
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, tw.Report)
	}

	return nil
}
