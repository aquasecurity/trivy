package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// TableWriter implements Writer and output in tabular form
type TableWriter struct {
	Severities []dbTypes.Severity
	Output     io.Writer
	Light      bool
}

// Write writes the result on standard output
func (tw TableWriter) Write(results Results) error {
	for _, result := range results {
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

	total, severityCount := tw.writeVulnerabilities(table, result.Vulnerabilities)

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

	fmt.Printf("\n%s\n", result.Target)
	fmt.Println(strings.Repeat("=", len(result.Target)))
	fmt.Printf("Total: %d (%s)\n\n", total, strings.Join(results, ", "))

	if len(result.Vulnerabilities) == 0 {
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
