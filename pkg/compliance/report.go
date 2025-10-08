package compliance

import (
	"io"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/compliance/report"
	"github.com/aquasecurity/trivy/internal/compliance/spec"
	compliance "github.com/aquasecurity/trivy/pkg/compliance/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Option struct {
	Format        types.Format
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
}

func BuildReport(scanResults []types.Results, cs compliance.Spec) (*compliance.Report, error) {
	// aggregate checks by ID
	aggregateChecksByID := spec.AggregateAllChecksBySpecID(scanResults, cs)

	// build compliance report results
	return report.BuildComplianceReportResults(aggregateChecksByID, cs.Spec), nil
}

func BuildSummary(cr *compliance.Report) *compliance.SummaryReport {
	return report.BuildSummary(cr)
}
