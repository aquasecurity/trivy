package k8s

import (
	"io"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
)

type TableWriter struct {
	Report     string
	Output     io.Writer
	Severities []dbTypes.Severity
}

func (tw TableWriter) Write(report Report) error {
	switch tw.Report {
	case allReport:
		t := pkgReport.TableWriter{Output: tw.Output, Severities: tw.Severities}
		for _, r := range report.Vulnerabilities {
			if r.Report.Results.Failed() {
				err := t.Write(r.Report)
				if err != nil {
					return err
				}
			}
		}
		for _, r := range report.Misconfigurations {
			if r.Report.Results.Failed() {
				err := t.Write(r.Report)
				if err != nil {
					return err
				}
			}
		}
	case summaryReport:
		writer := NewSummaryWriter(tw.Output, tw.Severities)
		return writer.Write(report)
	}
	return nil
}
