package report

import (
	"io"
	"sync"

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

func (tw TableWriter) columns() []string {
	return []string{ControlIDColumn, SeverityColumn, ControlNameColumn, StatusColumn, IssuesColumn}
}

func (tw TableWriter) Write(report *ComplianceReport) error {
	switch tw.Report {
	case allReport:
		t := pkgReport.Writer{Output: tw.Output, Severities: tw.Severities, ShowMessageOnce: &sync.Once{}}
		for _, cr := range report.Results {
			r := types.Report{Results: cr.Results}
			err := t.Write(r)
			if err != nil {
				return err
			}
		}
	case summaryReport:
		writer := NewSummaryWriter(tw.Output, tw.Severities, tw.columns())
		return writer.Write(report)
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, tw.Report)
	}

	return nil
}
