package report

import (
	"context"

	"golang.org/x/xerrors"

	spec2 "github.com/aquasecurity/trivy/internal/compliance/spec"
	ctypes "github.com/aquasecurity/trivy/pkg/compliance/types"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func (r ComplianceReport) empty() bool {
	return len(r.Results) == 0
}

// buildControlCheckResults create compliance results data
func buildControlCheckResults(checksMap map[string]types.Results, controls []iacTypes.Control) []*ControlCheckResult {
	var complianceResults []*ControlCheckResult
	for _, control := range controls {
		var results types.Results
		for _, c := range control.Checks {
			results = append(results, checksMap[c.ID]...)
		}
		complianceResults = append(complianceResults, &ControlCheckResult{
			Name:          control.Name,
			ID:            control.ID,
			Description:   control.Description,
			Severity:      string(control.Severity),
			DefaultStatus: control.DefaultStatus,
			Results:       results,
		})
	}
	return complianceResults
}

// buildComplianceReportResults create compliance results data
func buildComplianceReportResults(checksMap map[string]types.Results, s iacTypes.Spec) *ComplianceReport {
	controlCheckResult := buildControlCheckResults(checksMap, s.Controls)
	return &ComplianceReport{
		ID:               s.ID,
		Title:            s.Title,
		Description:      s.Description,
		Version:          s.Version,
		RelatedResources: s.RelatedResources,
		Results:          controlCheckResult,
	}
}

func BuildComplianceReport(scanResults []types.Results, cs spec2.ComplianceSpec) (*ComplianceReport, error) {
	// aggregate checks by ID
	aggregateChecksByID := spec2.AggregateAllChecksBySpecID(scanResults, cs)

	// build compliance report results
	return buildComplianceReportResults(aggregateChecksByID, cs.Spec), nil
}
