package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/types"
	"github.com/olekukonko/tablewriter"
)

type Results []Result

type Result struct {
	FileName        string `json:"file"`
	Vulnerabilities []types.Vulnerability
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
		table.Append([]string{v.PkgName, v.VulnerabilityID, vulnerability.ColorizeSeverity(v.Severity),
			v.InstalledVersion, v.FixedVersion, v.Title})
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
	out := map[string][]types.Vulnerability{}
	for _, result := range results {
		out[result.FileName] = result.Vulnerabilities
	}
	output, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprint(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}
	return nil
}
