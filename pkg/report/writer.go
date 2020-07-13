package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/olekukonko/tablewriter"
)

type Results []Result

type Result struct {
	Target          string                        `json:"Target"`
	Type            string                        `json:"Type,omitempty"`
	Vulnerabilities []types.DetectedVulnerability `json:"Vulnerabilities"`
}

func WriteResults(format string, output io.Writer, results Results, outputTemplate string, light bool) error {
	var writer Writer
	switch format {
	case "table":
		writer = &TableWriter{Output: output, Light: light}
	case "json":
		writer = &JsonWriter{Output: output}
	case "template":
		if strings.HasPrefix(outputTemplate, "@") {
			buf, err := ioutil.ReadFile(strings.TrimPrefix(outputTemplate, "@"))
			if err != nil {
				return xerrors.Errorf("Error retrieving template from path: %w", err)
			}
			outputTemplate = string(buf)
		}
		tmpl, err := template.New("output template").Funcs(template.FuncMap{
			"escapeXML": func(input string) string {
				escaped := &bytes.Buffer{}
				if err := xml.EscapeText(escaped, []byte(input)); err != nil {
					fmt.Printf("error while escapeString to XML: %v", err.Error())
					return input
				}
				return escaped.String()
			},
		}).Parse(outputTemplate)
		if err != nil {
			return xerrors.Errorf("error parsing template: %w", err)
		}
		writer = &TemplateWriter{Output: output, Template: tmpl}
	default:
		return xerrors.Errorf("unknown format: %v", format)
	}

	if err := writer.Write(results); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}
	return nil
}

type Writer interface {
	Write(Results) error
}

type TableWriter struct {
	Output io.Writer
	Light  bool
}

func (tw TableWriter) Write(results Results) error {
	for _, result := range results {
		tw.write(result)
	}
	return nil
}
func (tw TableWriter) write(result Result) {
	table := tablewriter.NewWriter(tw.Output)
	header := []string{"Library", "Vulnerability ID", "Severity", "Installed Version", "Fixed Version"}
	if !tw.Light {
		header = append(header, "Title")
	}
	table.SetHeader(header)

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
		var row []string
		if tw.Output == os.Stdout {
			row = []string{v.PkgName, v.VulnerabilityID, dbTypes.ColorizeSeverity(v.Severity),
				v.InstalledVersion, v.FixedVersion}
		} else {
			row = []string{v.PkgName, v.VulnerabilityID, v.Severity, v.InstalledVersion, v.FixedVersion}
		}

		if !tw.Light {
			row = append(row, title)
		}
		table.Append(row)
	}

	var results []string
	for _, severity := range dbTypes.SeverityNames {
		r := fmt.Sprintf("%s: %d", severity, severityCount[severity])
		results = append(results, r)
	}

	fmt.Printf("\n%s\n", result.Target)
	fmt.Println(strings.Repeat("=", len(result.Target)))
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
