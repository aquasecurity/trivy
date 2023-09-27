package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/tml"
	pkgReport "github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func writeServiceTable(report *Report, results types.Results, output io.Writer) error {

	t := table.New(output)

	t.SetHeaders("Service", "Misconfigurations", "Last Scanned")
	t.AddHeaders("Service", "Critical", "High", "Medium", "Low", "Unknown", "Last Scanned")
	t.SetRowLines(false)
	t.SetHeaderVerticalAlignment(table.AlignBottom)
	t.SetHeaderAlignment(table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignRight, table.AlignRight, table.AlignRight, table.AlignRight, table.AlignRight, table.AlignLeft)
	t.SetAutoMergeHeaders(true)
	t.SetHeaderColSpans(0, 1, 5, 1)

	// map service -> severity -> count
	grouped := make(map[string]map[string]int)
	// set zero counts for all services
	for _, service := range report.ServicesInScope {
		grouped[service] = make(map[string]int)
	}
	for _, result := range results {
		for _, misconfiguration := range result.Misconfigurations {
			service := misconfiguration.CauseMetadata.Service
			if _, ok := grouped[service]; !ok {
				grouped[service] = make(map[string]int)
			}
			grouped[service][misconfiguration.Severity]++
		}
	}

	var sortable []sortableRow
	for service, severityCounts := range grouped {
		sortable = append(sortable, sortableRow{
			name:   service,
			counts: severityCounts,
		})
	}
	sort.Slice(sortable, func(i, j int) bool { return sortable[i].name < sortable[j].name })
	for _, row := range sortable {
		var lastScanned string
		scanAgo := time.Since(report.Results[row.name].CreationTime).Truncate(time.Minute)
		switch {
		case scanAgo.Hours() >= 48:
			lastScanned = fmt.Sprintf("%d days ago", int(scanAgo.Hours()/24))
		case scanAgo.Hours() > 1:
			lastScanned = fmt.Sprintf("%d hours ago", int(scanAgo.Hours()))
		case scanAgo.Minutes() > 1:
			lastScanned = fmt.Sprintf("%d minutes ago", int(scanAgo.Minutes()))
		default:
			lastScanned = "just now"
		}

		t.AddRow(
			row.name,
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["CRITICAL"]), "CRITICAL"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["HIGH"]), "HIGH"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["MEDIUM"]), "MEDIUM"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["LOW"]), "LOW"),
			pkgReport.ColorizeSeverity(strconv.Itoa(row.counts["UNKNOWN"]), "UNKNOWN"),
			lastScanned,
		)
	}

	// render scan title
	_ = tml.Fprintf(output, "\n<bold>Scan Overview for %s Account %s</bold>\n", report.Provider, report.AccountID)

	// render table
	t.Render()

	return nil
}
