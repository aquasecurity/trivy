package report

import (
	"context"
	"io"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	allReport     = "all"
	summaryReport = "summary"
)

type Option struct {
	Format        types.Format
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
}

// ComplianceReport represents a kubernetes scan report
type ComplianceReport struct {
	ID               string
	Title            string
	Description      string
	Version          string
	RelatedResources []string
	Results          []*ControlCheckResult
}

type ControlCheckResult struct {
	ID            string
	Name          string
	Description   string
	DefaultStatus iacTypes.ControlStatus `json:",omitempty"`
	Severity      string
	Results       types.Results
}

// SummaryReport represents a kubernetes scan report with consolidated findings
type SummaryReport struct {
	SchemaVersion   int `json:",omitempty"`
	ID              string
	Title           string
	SummaryControls []ControlCheckSummary `json:",omitempty"`
}

type ControlCheckSummary struct {
	ID        string
	Name      string
	Severity  string
	TotalFail *int `json:",omitempty"`
}

// Writer defines the result write operation
type Writer interface {
	Write(ComplianceReport) error
}

// Write writes the results in the given format
func Write(ctx context.Context, report *ComplianceReport, option Option) error {
	switch option.Format {
	case types.FormatJSON:
		jwriter := JSONWriter{
			Output: option.Output,
			Report: option.Report,
		}
		return jwriter.Write(report)
	case types.FormatTable:
		if !report.empty() {
			complianceWriter := &TableWriter{
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

func BuildComplianceReport(scanResults []types.Results, cs spec.ComplianceSpec) (*ComplianceReport, error) {
	// aggregate checks by ID
	aggregateChecksByID := spec.AggregateAllChecksBySpecID(scanResults, cs)

	// build compliance report results
	return buildComplianceReportResults(aggregateChecksByID, cs.Spec), nil
}
