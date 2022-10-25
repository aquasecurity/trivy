package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/table"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	pkgReport "github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

type SummaryWriter struct {
	Output           io.Writer
	Severities       []string
	SeverityHeadings []string
	ColumnsHeading   []string
}

func NewSummaryWriter(output io.Writer, requiredSevs []dbTypes.Severity, columnHeading []string) SummaryWriter {
	var severities []string
	var severityHeadings []string
	severities, severityHeadings = getRequiredSeverities(requiredSevs)
	return SummaryWriter{
		Output:           output,
		Severities:       severities,
		SeverityHeadings: severityHeadings,
		ColumnsHeading:   columnHeading,
	}
}

func ColumnHeading(securityChecks, components, availableColumns []string) []string {
	columns := []string{NamespaceColumn, ResourceColumn}
	securityOptions := make(map[string]interface{}, 0)
	//maintain column order (vuln,config,secret)
	for _, check := range securityChecks {
		switch check {
		case types.SecurityCheckVulnerability:
			securityOptions[VulnerabilitiesColumn] = nil
		case types.SecurityCheckConfig:
			if slices.Contains(components, workloadComponent) {
				securityOptions[MisconfigurationsColumn] = nil
			}
			if slices.Contains(components, infraComponent) {
				securityOptions[InfraAssessmentColumn] = nil
			}
		case types.SecurityCheckSecret:
			securityOptions[SecretsColumn] = nil
		case types.SecurityCheckRbac:
			securityOptions[RbacAssessmentColumn] = nil
		}
	}
	for _, col := range availableColumns {
		if _, ok := securityOptions[col]; ok {
			columns = append(columns, col)
		}
	}
	return columns
}

// Write writes the results in a summarized table format
func (s SummaryWriter) Write(report Report) error {
	// no report column to print
	if len(s.ColumnsHeading) == 2 {
		return nil
	}
	consolidated := report.consolidate()

	if _, err := fmt.Fprintln(s.Output); err != nil {
		return xerrors.Errorf("failed to write summary report: %w", err)
	}

	if _, err := fmt.Fprintln(s.Output, report.name); err != nil {
		return xerrors.Errorf("failed to write summary report title: %w", err)
	}

	t := table.New(s.Output)
	t.SetRowLines(false)
	configureHeader(s, t, s.ColumnsHeading)

	sort.Slice(consolidated.Findings, func(i, j int) bool {
		return consolidated.Findings[i].Namespace > consolidated.Findings[j].Namespace
	})

	for _, finding := range consolidated.Findings {
		if !finding.Results.Failed() {
			continue
		}
		vCount, mCount, sCount := accumulateSeverityCounts(finding)
		name := fmt.Sprintf("%s/%s", finding.Kind, finding.Name)
		rowParts := []string{finding.Namespace, name}

		if slices.Contains(s.ColumnsHeading, VulnerabilitiesColumn) {
			rowParts = append(rowParts, s.generateSummary(vCount)...)
		}

		if slices.Contains(s.ColumnsHeading, MisconfigurationsColumn) ||
			slices.Contains(s.ColumnsHeading, RbacAssessmentColumn) ||
			slices.Contains(s.ColumnsHeading, InfraAssessmentColumn) {
			rowParts = append(rowParts, s.generateSummary(mCount)...)
		}

		if slices.Contains(s.ColumnsHeading, SecretsColumn) {
			rowParts = append(rowParts, s.generateSummary(sCount)...)
		}

		t.AddRow(rowParts...)
	}

	t.Render()

	keyParts := []string{"Severities:"}
	for _, s := range s.Severities {
		keyParts = append(keyParts, fmt.Sprintf("%s=%s", s[:1], pkgReport.ColorizeSeverity(s, s)))
	}

	_, _ = fmt.Fprintln(s.Output, strings.Join(keyParts, " "))
	_, _ = fmt.Fprintln(s.Output)
	return nil
}

func (s SummaryWriter) generateSummary(sevCount map[string]int) []string {
	var parts []string

	for _, sev := range s.Severities {
		if count, ok := sevCount[sev]; ok {
			parts = append(parts, pkgReport.ColorizeSeverity(strconv.Itoa(count), sev))
		} else {
			parts = append(parts, " ")
		}
	}

	return parts
}

func getRequiredSeverities(requiredSevs []dbTypes.Severity) ([]string, []string) {
	requiredSevOrder := []dbTypes.Severity{dbTypes.SeverityCritical,
		dbTypes.SeverityHigh, dbTypes.SeverityMedium,
		dbTypes.SeverityLow, dbTypes.SeverityUnknown}
	var severities []string
	var severityHeadings []string
	for _, sev := range requiredSevOrder {
		for _, p := range requiredSevs {
			if p == sev {
				severities = append(severities, sev.String())
				severityHeadings = append(severityHeadings, strings.ToUpper(sev.String()[:1]))
				continue
			}
		}
	}
	return severities, severityHeadings
}

func accumulateSeverityCounts(finding Resource) (map[string]int, map[string]int, map[string]int) {
	vCount := make(map[string]int)
	mCount := make(map[string]int)
	sCount := make(map[string]int)
	for _, r := range finding.Results {
		for _, rv := range r.Vulnerabilities {
			vCount[rv.Severity] = vCount[rv.Severity] + 1
		}
		for _, rv := range r.Misconfigurations {
			mCount[rv.Severity] = mCount[rv.Severity] + 1
		}
		for _, rv := range r.Secrets {
			sCount[rv.Severity] = sCount[rv.Severity] + 1
		}
	}
	return vCount, mCount, sCount
}

func configureHeader(s SummaryWriter, t *table.Table, columnHeading []string) {
	sevCount := len(s.Severities)
	if len(columnHeading) > 2 {
		headerRow := []string{columnHeading[0], columnHeading[1]}
		//  vulnerabilities headings
		count := len(columnHeading) - len(headerRow)
		colSpan := []int{1, 1}
		headerAlignment := []table.Alignment{table.AlignLeft, table.AlignLeft}
		for i := 0; i < count; i++ {
			headerRow = append(headerRow, s.SeverityHeadings...)
			colSpan = append(colSpan, sevCount)
			headerAlignment = append(headerAlignment, table.AlignCenter)
		}
		t.SetHeaders(columnHeading...)
		t.AddHeaders(headerRow...)
		t.SetAlignment(headerAlignment...)
		t.SetAutoMergeHeaders(true)
		t.SetHeaderColSpans(0, colSpan...)
	}
}
