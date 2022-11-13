package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/aquasecurity/tml"

	"golang.org/x/term"

	"github.com/aquasecurity/table"
	pkgReport "github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

type sortableRow struct {
	name   string
	counts map[string]int
}

func writeResourceTable(report *Report, results types.Results, output io.Writer, service string) error {

	termWidth, _, err := term.GetSize(0)
	if err != nil {
		termWidth = 80
	}
	maxWidth := termWidth - 48
	if maxWidth < 20 {
		maxWidth = 20
	}

	t := table.New(output)
	t.SetColumnMaxWidth(maxWidth)
	t.SetHeaders("Resource", "Misconfigurations")
	t.AddHeaders("Resource", "Critical", "High", "Medium", "Low", "Unknown")
	t.SetHeaderVerticalAlignment(table.AlignBottom)
	t.SetHeaderAlignment(table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter)
	t.SetAlignment(table.AlignLeft, table.AlignRight, table.AlignRight, table.AlignRight, table.AlignRight, table.AlignRight)
	t.SetRowLines(false)
	t.SetAutoMergeHeaders(true)
	t.SetHeaderColSpans(0, 1, 5)

	// map resource -> severity -> count
	grouped := make(map[string]map[string]int)
	for _, result := range results {
		for _, misconfiguration := range result.Misconfigurations {
			if misconfiguration.CauseMetadata.Service != service {
				continue
			}
			if _, ok := grouped[misconfiguration.CauseMetadata.Resource]; !ok {
				grouped[misconfiguration.CauseMetadata.Resource] = make(map[string]int)
			}
			grouped[misconfiguration.CauseMetadata.Resource][misconfiguration.Severity]++
		}
	}

	var sortable []sortableRow
	for resource, severityCounts := range grouped {
		sortable = append(sortable, sortableRow{
			name:   resource,
			counts: severityCounts,
		})
	}
	sort.Slice(sortable, func(i, j int) bool { return sortable[i].name < sortable[j].name })
	for _, row := range sortable {
		t.AddRow(
			row.name,
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["CRITICAL"]), "CRITICAL"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["HIGH"]), "HIGH"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["MEDIUM"]), "MEDIUM"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["LOW"]), "LOW"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["UNKNOWN"]), "UNKNOWN"),
		)
	}

	// render scan title
	_ = tml.Fprintf(output, "\n<bold>Resource Summary for Service '%s' (%s Account %s)</bold>\n", service, report.Provider, report.AccountID)

	// render table
	if len(sortable) > 0 {
		t.Render()
	} else {
		_, _ = fmt.Fprint(output, "\nNo problems detected.\n")
	}

	return nil
}
