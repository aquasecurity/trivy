package report

import (
	"context"
	"fmt"
	"io"
	"strings"

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

	TableMode []types.TableMode // For `--report all` only
}

const (
	NamespaceColumn         = "Namespace"
	ResourceColumn          = "Resource"
	VulnerabilitiesColumn   = "Vulnerabilities"
	MisconfigurationsColumn = "Misconfigurations"
	SecretsColumn           = "Secrets"
	RbacAssessmentColumn    = "RBAC Assessment"
)

func WorkloadColumns() []string {
	return []string{
		VulnerabilitiesColumn,
		MisconfigurationsColumn,
		SecretsColumn,
	}
}

func RoleColumns() []string {
	return []string{RbacAssessmentColumn}
}

func InfraColumns() []string {
	return []string{
		VulnerabilitiesColumn,
		MisconfigurationsColumn,
		SecretsColumn,
	}
}

func (tw TableWriter) Write(ctx context.Context, report Report) error {
	switch tw.Report {
	case AllReport:
		t := pkgReport.NewWriter(pkgReport.Options{
			Output:     tw.Output,
			Severities: tw.Severities,
			// k8s has its own summary report, so we only need to show the detailed tables here
			TableModes: []types.TableMode{
				types.Detailed,
			},
		})
		for i, r := range report.Resources {
			if r.Report.Results.Failed() {
				updateTargetContext(&report.Resources[i])
				err := t.Write(ctx, r.Report)
				if err != nil {
					return err
				}
			}
		}
	case SummaryReport:
		writer := NewSummaryWriter(tw.Output, tw.Severities, tw.ColumnHeading)
		return writer.Write(report)
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, tw.Report)
	}

	return nil
}

// updateTargetContext add context namespace, kind and name to the target
func updateTargetContext(r *Resource) {
	targetName := fmt.Sprintf("namespace: %s, %s: %s", r.Namespace, strings.ToLower(r.Kind), r.Name)
	if r.Kind == "NodeComponents" || r.Kind == "NodeInfo" {
		targetName = fmt.Sprintf("node: %s", r.Name)
	}
	for i := range r.Report.Results {
		r.Report.Results[i].Target = targetName
	}
}
