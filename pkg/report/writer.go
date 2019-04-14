package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/knqyf263/trivy/pkg/vulnsrc/nvd"

	"github.com/knqyf263/trivy/pkg/types"
	"github.com/olekukonko/tablewriter"
)

type Result struct {
	FileName        string `json:"file"`
	Vulnerabilities []types.Vulnerability
}

type Writer interface {
	Write(*Result) error
}

type TableWriter struct {
	Output io.Writer
}

func (tw TableWriter) Write(result *Result) error {
	table := tablewriter.NewWriter(tw.Output)
	table.SetHeader([]string{"Library", "Vulnerability ID", "Severity", "Title"})

	severityCount := map[string]int{}
	for _, v := range result.Vulnerabilities {
		severityCount[v.Severity]++
		table.Append([]string{v.LibraryName, v.VulnerabilityID, nvd.ColorizeSeverity(v.Severity), v.Title})
	}

	var results []string
	for _, severity := range nvd.SeverityNames {
		r := fmt.Sprintf("%s: %d", severity, severityCount[severity])
		results = append(results, r)
	}

	fmt.Printf("\n%s\n", result.FileName)
	fmt.Println(strings.Repeat("=", len(result.FileName)))
	fmt.Printf("Total: %d (%s)\n\n", len(result.Vulnerabilities), strings.Join(results, ", "))

	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.Render()
	return nil
}

type JsonWriter struct {
	Output io.Writer
}

func (jw JsonWriter) Write(result *Result) error {
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	if _, err = fmt.Fprint(jw.Output, string(output)); err != nil {
		return err
	}
	return nil
}
