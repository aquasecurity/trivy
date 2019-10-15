package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/olekukonko/tablewriter"
)

type Results []Result

type Result struct {
	FileName        string                                `json:"Target"`
	Vulnerabilities []vulnerability.DetectedVulnerability `json:"Vulnerabilities"`
}

type Writer interface {
	Write(Results) error
}

type TableWriter struct {
	Output io.Writer
}

func (tw TableWriter) Write(results Results) error {
	for _, result := range results {
		tw.write(result)
	}
	return nil
}
func (tw TableWriter) write(result Result) {
	table := tablewriter.NewWriter(tw.Output)
	table.SetHeader([]string{"Library", "Vulnerability ID", "Severity", "Installed Version", "Fixed Version", "Title"})

	severityCount := map[string]int{}
	for _, v := range result.Vulnerabilities {
		severityCount[v.Severity]++

		title := v.Title
		if title == "" {
			title = v.Description
		}
		splittedTitle := strings.Split(title, " ")
		if len(splittedTitle) >= 12 {
			title = strings.Join(splittedTitle[:12], " ") + "..."
		}
		if tw.Output == os.Stdout {
			table.Append([]string{v.PkgName, v.VulnerabilityID, vulnerability.ColorizeSeverity(v.Severity),
				v.InstalledVersion, v.FixedVersion, title})
		} else {
			table.Append([]string{v.PkgName, v.VulnerabilityID, v.Severity, v.InstalledVersion, v.FixedVersion, title})
		}
	}

	var results []string
	for _, severity := range vulnerability.SeverityNames {
		r := fmt.Sprintf("%s: %d", severity, severityCount[severity])
		results = append(results, r)
	}

	fmt.Printf("\n%s\n", result.FileName)
	fmt.Println(strings.Repeat("=", len(result.FileName)))
	fmt.Printf("Total: %d (%s)\n\n", len(result.Vulnerabilities), strings.Join(results, ", "))

	if len(result.Vulnerabilities) == 0 {
		return
	}

	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.Render()
	return
}

type JsonWriter struct {
	Output io.Writer
}

func (jw JsonWriter) Write(results Results) error {
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprint(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}
	return nil
}

type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

func (tw TemplateWriter) Write(results Results) error {
	err := tw.Template.Execute(tw.Output, results)
	if err != nil {
		return xerrors.Errorf("failed to write with template: %w", err)
	}
	return nil
}
