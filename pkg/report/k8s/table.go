package k8s

import (
	"fmt"
	"io"
	"os"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/olekukonko/tablewriter"
)

// TableWriter implements Writer and output in tabular form
type TableWriter struct {
	Output io.Writer
}

// Write writes the result on standard output
func (tw TableWriter) Write(report types.K8sReport) error {
	data := make([][]string, 0)

	for _, resource := range report.Resources {
		d := make([]string, 5)

		d[0] = resource.Namespace
		d[1] = resource.Kind
		d[2] = resource.Name

		d[3] = summaryVulnerabilities(resource.Results)
		d[4] = summaryMisconfigurations(resource.Results)

		data = append(data, d)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.AppendBulk(data)

	table.SetHeader([]string{
		"Namespace",
		"Kind",
		"Name",
		"MisConfigurations",
		"Vunerabilities",
	})

	table.SetRowLine(true)
	table.Render() // Send output

	return nil
}

func summaryVulnerabilities(results types.Results) string {
	var critical, high, medium, low, unknown int

	for _, r := range results {
		for _, vuln := range r.Vulnerabilities {
			switch vuln.Severity {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			case "LOW":
				low++
			case "UNKNOWN":
				unknown++
			}

		}
	}

	return fmt.Sprintf(
		"CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d, UNKNOWN: %d",
		critical,
		high,
		medium,
		low,
		unknown,
	)
}

func summaryMisconfigurations(results types.Results) string {
	var critical, high, medium, low, unknown int

	for _, r := range results {
		for _, mis := range r.Misconfigurations {
			switch mis.Severity {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			case "LOW":
				low++
			case "UNKNOWN":
				unknown++
			}

		}
	}

	return fmt.Sprintf(
		"CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d, UNKNOWN: %d",
		critical,
		high,
		medium,
		low,
		unknown,
	)
}
