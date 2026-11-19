package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/trivy/pkg/types"
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
			ccm.TotalFail = new(countFailed(control.Results))
		}
		ccma = append(ccma, ccm)
	}
	return &SummaryReport{
		ID:              cr.ID,
		Title:           cr.Title,
		SummaryControls: ccma,
	}
}

// countFailed returns the number of control results that hold a failing finding.
// A misconfiguration is only a failure when its status says so, which is the rule
// [types.Results.Failed] applies; the other finding types fail by presence.
func countFailed(results types.Results) int {
	var n int
	for _, r := range results {
		// With --include-non-failures a passed check reaches the report as well,
		// and it is not an issue for the control.
		if len(r.Misconfigurations) > 0 && !hasFailedMisconf(r.Misconfigurations) {
			continue
		}
		n++
	}
	return n
}

func hasFailedMisconf(misconfs []types.DetectedMisconfiguration) bool {
	for _, m := range misconfs {
		if m.Status == types.MisconfStatusFailure {
			return true
		}
	}
	return false
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
