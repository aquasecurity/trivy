package report

import (
	"fmt"
	"sort"
	"strconv"

	"golang.org/x/term"

	"github.com/aquasecurity/table"
	pkgReport "github.com/aquasecurity/trivy/pkg/report/table"
)

type sortableRow struct {
	name   string
	counts map[string]int
}

func writeResourceTable(report *Report, option Option) error {

	t := table.New(option.Output)

	w, _, err := term.GetSize(0)
	if err != nil {
		w = 80
	}
	maxWidth := w - 60
	if maxWidth < 20 {
		maxWidth = 20
	}

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
	result := report.Results[option.Service].Result
	for _, misconfiguration := range result.Misconfigurations {
		if _, ok := grouped[misconfiguration.CauseMetadata.Resource]; !ok {
			grouped[misconfiguration.CauseMetadata.Resource] = make(map[string]int)
		}
		grouped[misconfiguration.CauseMetadata.Resource][misconfiguration.Severity]++
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
	_, _ = fmt.Fprintf(option.Output, "\n\x1b[1mResource Summary for Service '%s' (%s Account %s)\x1b[0m\n", option.Service, report.Provider, report.AccountID)

	// render table
	t.Render()

	// TODO: render individual results if necessary

	// render cache info
	if option.FromCache {
		_, _ = fmt.Fprintf(option.Output, "\n\x1b[34mThis scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.\x1b[0m\n")
	}

	return nil
}
