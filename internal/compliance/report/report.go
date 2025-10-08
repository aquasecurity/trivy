package report

import (
	ctypes "github.com/aquasecurity/trivy/pkg/compliance/types"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// BuildComplianceReportResults create compliance results data
func BuildComplianceReportResults(checksMap map[string]types.Results, s iacTypes.Spec) *ctypes.Report {
	controlCheckResult := buildControlCheckResults(checksMap, s.Controls)
	return &ctypes.Report{
		ID:               s.ID,
		Title:            s.Title,
		Description:      s.Description,
		Version:          s.Version,
		RelatedResources: s.RelatedResources,
		Results:          controlCheckResult,
	}
}

// buildControlCheckResults create compliance results data
func buildControlCheckResults(checksMap map[string]types.Results, controls []iacTypes.Control) []*ctypes.ControlCheckResult {
	var complianceResults []*ctypes.ControlCheckResult
	for _, control := range controls {
		var results types.Results
		for _, c := range control.Checks {
			results = append(results, checksMap[c.ID]...)
		}
		complianceResults = append(complianceResults, &ctypes.ControlCheckResult{
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
