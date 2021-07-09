package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// TableWriter implements Writer and output in tabular form
type TableWriter struct {
	Severities       []dbTypes.Severity
	Output           io.Writer
	Light            bool
	IncludeSuccesses bool
}

// Write writes the result on standard output
func (tw TableWriter) Write(report Report) error {
	for _, result := range report.Results {
		// Skip zero vulnerabilities on Java archives (JAR/WAR/EAR)
		if result.Type == ftypes.Jar && len(result.Vulnerabilities) == 0 {
			continue
		}
		tw.write(result)
	}
	return nil
}

func (tw TableWriter) write(result Result) {
	table := tablewriter.NewWriter(tw.Output)

	var total int
	var severityCount map[string]int
	if len(result.Vulnerabilities) != 0 {
		total, severityCount = tw.writeVulnerabilities(table, result.Vulnerabilities)
	} else if len(result.Misconfigurations) != 0 {
		severityCount = tw.writeMisconfigurations(table, result.Misconfigurations)
	}

	var severities []string
	for _, sev := range tw.Severities {
		severities = append(severities, sev.String())
	}

	var results []string
	for _, severity := range dbTypes.SeverityNames {
		if !utils.StringInSlice(severity, severities) {
			continue
		}
		r := fmt.Sprintf("%s: %d", severity, severityCount[severity])
		results = append(results, r)
	}

	target := result.Target
	if result.Class != ClassOSPkg {
		target += fmt.Sprintf(" (%s)", result.Type)
	}

	fmt.Printf("\n%s\n", target)
	fmt.Println(strings.Repeat("=", len(target)))
	if result.MisconfSummary != nil {
		// for misconfigurations
		summary := result.MisconfSummary
		fmt.Printf("Tests: %d (SUCCESSES: %d, FAILURES: %d, EXCEPTIONS: %d)\n",
			summary.Successes+summary.Failures+summary.Exceptions, summary.Successes, summary.Failures, summary.Exceptions)
		fmt.Printf("Failures: %d (%s)\n\n", summary.Failures, strings.Join(results, ", "))
	} else {
		// for vulnerabilities
		fmt.Printf("Total: %d (%s)\n\n", total, strings.Join(results, ", "))
	}

	if len(result.Vulnerabilities) == 0 && len(result.Misconfigurations) == 0 {
		return
	}

	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.Render()
	return
}

func (tw TableWriter) writeVulnerabilities(table *tablewriter.Table, vulns []types.DetectedVulnerability) (int, map[string]int) {
	header := []string{"Library", "Vulnerability ID", "Severity", "Installed Version", "Fixed Version"}
	if !tw.Light {
		header = append(header, "Title")
	}
	table.SetHeader(header)
	severityCount := tw.setVulnerabilityRows(table, vulns)

	return len(vulns), severityCount
}

func (tw TableWriter) writeMisconfigurations(table *tablewriter.Table, misconfs []types.DetectedMisconfiguration) map[string]int {
	table.SetColWidth(40)

	alignment := []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT}
	header := []string{"Type", "Misconf ID", "Check", "Severity", "Status", "Message"}

	if !tw.IncludeSuccesses {
		// Remove status
		statusPos := 4
		alignment = append(alignment[:statusPos], alignment[statusPos+1:]...)
		header = append(header[:statusPos], header[statusPos+1:]...)
	}

	table.SetColumnAlignment(alignment)
	table.SetHeader(header)
	severityCount := tw.setMisconfRows(table, misconfs)

	return severityCount
}

func (tw TableWriter) setVulnerabilityRows(table *tablewriter.Table, vulns []types.DetectedVulnerability) map[string]int {
	severityCount := map[string]int{}
	for _, v := range vulns {
		severityCount[v.Severity]++

		title := v.Title
		if title == "" {
			title = v.Description
		}
		splitTitle := strings.Split(title, " ")
		if len(splitTitle) >= 12 {
			title = strings.Join(splitTitle[:12], " ") + "..."
		}

		if len(v.PrimaryURL) > 0 {
			r := strings.NewReplacer("https://", "", "http://", "")
			title = fmt.Sprintf("%s -->%s", title, r.Replace(v.PrimaryURL))
		}

		var row []string
		if tw.Output == os.Stdout {
			row = []string{v.PkgName, v.VulnerabilityID, dbTypes.ColorizeSeverity(v.Severity),
				v.InstalledVersion, v.FixedVersion}
		} else {
			row = []string{v.PkgName, v.VulnerabilityID, v.Severity, v.InstalledVersion, v.FixedVersion}
		}

		if !tw.Light {
			row = append(row, strings.TrimSpace(title))
		}
		table.Append(row)
	}
	return severityCount
}

func (tw TableWriter) setMisconfRows(table *tablewriter.Table, misconfs []types.DetectedMisconfiguration) map[string]int {
	severityCount := map[string]int{}
	for _, misconf := range misconfs {
		if misconf.Status == types.StatusFailure {
			severityCount[misconf.Severity]++
			if misconf.PrimaryURL != "" {
				primaryURL := strings.TrimPrefix(misconf.PrimaryURL, "https://")
				misconf.Message = fmt.Sprintf("%s -->%s", misconf.Message, primaryURL)
			}
		}

		var row []string
		if tw.Output == os.Stdout {
			if misconf.Status == types.StatusPassed {
				row = []string{misconf.Type, misconf.ID, misconf.Title, color.New(color.FgGreen).Sprint(misconf.Severity),
					color.New(color.FgGreen).Sprint(misconf.Status), misconf.Message}
			} else {
				row = []string{misconf.Type, misconf.ID, misconf.Title, dbTypes.ColorizeSeverity(misconf.Severity),
					color.New(color.FgRed).Sprint(misconf.Status), misconf.Message}
			}
		} else {
			row = []string{misconf.Type, misconf.ID, misconf.Title, misconf.Severity, string(misconf.Status), misconf.Message}
		}

		if !tw.IncludeSuccesses {
			// Remove status
			row = append(row[:4], row[5:]...)
		}

		table.Append(row)
	}
	return severityCount
}
