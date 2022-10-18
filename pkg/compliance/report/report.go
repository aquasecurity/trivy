package report

import (
	"io"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

const (
	allReport     = "all"
	summaryReport = "summary"

	tableFormat = "table"
	jsonFormat  = "json"
)

type Option struct {
	Format        string
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
}

// ComplianceReport represents a kubernetes scan report
type ComplianceReport struct {
	ID               string                `json:"id"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Version          string                `json:"severity"`
	RelatedResources []string              `json:"relatedResources"`
	ControlResults   []*ControlCheckResult `json:"checksResults"`
}

type ControlCheckResult struct {
	ControlCheckID     string        `json:"id"`
	ControlName        string        `json:"name"`
	ControlDescription string        `json:"description"`
	ControlSeverity    string        `json:"severity"`
	Checks             types.Results `json:"checksResults"`
}

// ConsolidatedReport represents a kubernetes scan report with consolidated findings
type SummaryReport struct {
	SchemaVersion   int `json:",omitempty"`
	ReportID        string
	ReportTitle     string
	SummaryControls []ControlCheckSummary `json:",omitempty"`
}

type ControlCheckSummary struct {
	ControlCheckID  string  `json:"id"`
	ControlName     string  `json:"name"`
	ControlSeverity string  `json:"severity"`
	TotalPass       float32 `json:"totalPass"`
	TotalFail       float32 `json:"totalFail"`
}

// Writer defines the result write operation
type Writer interface {
	Write(ComplianceReport) error
}

// Write writes the results in the give format
func Write(report *ComplianceReport, option Option, showEmpty bool) error {
	switch option.Format {
	case jsonFormat:
		jwriter := JSONWriter{Output: option.Output, Report: option.Report}
		return jwriter.Write(report)
	case tableFormat:
		if !report.empty() || showEmpty {
			complianceWriter := &TableWriter{
				Output:     option.Output,
				Report:     option.Report,
				Severities: option.Severities,
			}
			err := complianceWriter.Write(report)
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
	return len(r.ControlResults) == 0
}

// buildControlCheckResults create compliance results data
func buildControlCheckResults(checksMap map[string]types.Results, controls []spec.Control) []*ControlCheckResult {
	complianceResults := make([]*ControlCheckResult, 0)
	for _, control := range controls {
		cr := ControlCheckResult{}
		cr.ControlName = control.Name
		cr.ControlCheckID = control.ID
		cr.ControlDescription = control.Description
		cr.ControlSeverity = string(control.Severity)
		for _, c := range control.Checks {
			cr.Checks = append(cr.Checks, checksMap[c.ID]...)
		}
		complianceResults = append(complianceResults, &cr)
	}
	return complianceResults
}

// buildComplianceReportResults create compliance results data
func buildComplianceReportResults(checksMap map[string]types.Results, spec spec.Spec) *ComplianceReport {
	controlCheckResult := buildControlCheckResults(checksMap, spec.Controls)
	return &ComplianceReport{
		ID:               spec.ID,
		Title:            spec.Title,
		Description:      spec.Description,
		Version:          spec.Version,
		RelatedResources: spec.RelatedResources,
		ControlResults:   controlCheckResult,
	}
}

func BuildComplianceReport(scanResults []types.Results, complianceSpec string) (*ComplianceReport, error) {
	// load compliance spec
	cs := spec.ComplianceSpec{}
	err := yaml.Unmarshal([]byte(complianceSpec), &cs)
	if err != nil {
		return nil, err
	}
	// aggregate checks by ID
	aggregateChecksByID := spec.AggregateChecksByID(scanResults, cs.Spec.Controls)

	// build compliance report results
	return buildComplianceReportResults(aggregateChecksByID, cs.Spec), nil
}
