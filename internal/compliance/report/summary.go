package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/table"
)

func BuildSummary(cr *ComplianceReport) *SummaryReport {
	var ccma []ControlCheckSummary
	for _, control := range cr.Results {
		ccm := ControlCheckSummary{
			ID:       control.ID,
			Name:     control.Name,
			Severity: control.Severity,
		}
		if !strings.Contains(control.Name, "Manual") {
			ccm.TotalFail = lo.ToPtr(len(control.Results))
		}
		ccma = append(ccma, ccm)
	}
	return &SummaryReport{
		ID:              cr.ID,
		Title:           cr.Title,
		SummaryControls: ccma,
	}
}

type SummaryWriter struct {
	Output io.Writer
}

func NewSummaryWriter(output io.Writer) SummaryWriter {
	return SummaryWriter{
		Output: output,
	}
}

// Write writes the results in a summarized table format
func (s SummaryWriter) Write(report *ComplianceReport) error {
	if _, err := fmt.Fprintln(s.Output); err != nil {
		return xerrors.Errorf("failed to write summary report: %w", err)
	}

	if _, err := fmt.Fprintf(s.Output, "Summary Report for compliance: %s\n", report.Title); err != nil {
		return xerrors.Errorf("failed to write summary report: %w", err)
	}
	sr := BuildSummary(report)
	t := table.New(s.Output)
	t.SetRowLines(false)
	configureHeader(t, s.columns())

	for _, summaryControl := range sr.SummaryControls {
		rowParts := s.generateSummary(summaryControl)
		t.AddRow(rowParts...)
	}

	t.Render()

	return nil
}

func (s SummaryWriter) columns() []string {
	return []string{
		ControlIDColumn,
		SeverityColumn,
		ControlNameColumn,
		StatusColumn,
		IssuesColumn,
	}
}

func (s SummaryWriter) generateSummary(summaryControls ControlCheckSummary) []string {
	// "-" means manual checks
	numOfIssues := "-"
	status := "-"
	if summaryControls.TotalFail != nil {
		if *summaryControls.TotalFail == 0 {
			status = "PASS"
		} else {
			status = "FAIL"
		}
		numOfIssues = strconv.Itoa(*summaryControls.TotalFail)
	}
	return []string{
		summaryControls.ID,
		summaryControls.Severity,
		summaryControls.Name,
		status,
		numOfIssues,
	}
}

func configureHeader(t *table.Table, columnHeading []string) {
	headerAlignment := []table.Alignment{
		table.AlignLeft,
		table.AlignCenter,
		table.AlignLeft,
		table.AlignCenter,
		table.AlignCenter,
	}
	t.SetHeaders(columnHeading...)
	t.SetAlignment(headerAlignment...)
	t.SetAutoMergeHeaders(true)
}
