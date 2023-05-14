package report

import (
	"io"
	"sync"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	pkgReport "github.com/aquasecurity/trivy/pkg/report/table"
)

type TableWriter struct {
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
}

const (
	NamespaceColumn         = "Namespace"
	ResourceColumn          = "Resource"
	VulnerabilitiesColumn   = "Vulnerabilities"
	MisconfigurationsColumn = "Misconfigurations"
	SecretsColumn           = "Secrets"
	RbacAssessmentColumn    = "RBAC Assessment"
	InfraAssessmentColumn   = "Kubernetes Infra Assessment"
)

func WorkloadColumns() []string {
	return []string{VulnerabilitiesColumn, MisconfigurationsColumn, SecretsColumn}
}

func RoleColumns() []string {
	return []string{RbacAssessmentColumn}
}

func InfraColumns() []string {
	return []string{InfraAssessmentColumn}
}

func (tw TableWriter) Write(report Report) error {
	switch tw.Report {
	case allReport:
		t := pkgReport.Writer{Output: tw.Output, Severities: tw.Severities, ShowMessageOnce: &sync.Once{}}
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
		writer := NewSummaryWriter(tw.Output, tw.Severities, tw.ColumnHeading)
		return writer.Write(report)
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, tw.Report)
	}

	return nil
}
