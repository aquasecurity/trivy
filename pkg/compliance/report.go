package compliance

import (
	"io"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/compliance/spec"
	ctypes "github.com/aquasecurity/trivy/pkg/compliance/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Option struct {
	Format        types.Format
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
}

func BuildReport(scanResults []types.Results, cs spec.ComplianceSpec) (*ctypes.ComplianceReport, error) {
	// aggregate checks by ID
	aggregateChecksByID := spec.AggregateAllChecksBySpecID(scanResults, cs)

	// build compliance report results
	return buildComplianceReportResults(aggregateChecksByID, cs.Spec), nil
}
