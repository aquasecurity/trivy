package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// Now returns the current time
var Now = time.Now

// Results to hold list of Result
type Results []Result

// Result to hold image scan results
type Result struct {
	Target          string                        `json:"Target"`
	Type            string                        `json:"Type,omitempty"`
	Packages        []ftypes.Package              `json:"Packages,omitempty"`
	Vulnerabilities []types.DetectedVulnerability `json:"Vulnerabilities"`
}

// WriteResults writes the result to output, format as passed in argument
func WriteResults(format string, output io.Writer, severities []dbTypes.Severity, results Results, outputTemplate string, light bool) error {
	var writer Writer
	switch format {
	case "table":
		writer = &TableWriter{Output: output, Light: light, Severities: severities}
	case "json":
		writer = &JSONWriter{Output: output}
	case "template":
		var err error
		if writer, err = NewTemplateWriter(output, outputTemplate); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	default:
		return xerrors.Errorf("unknown format: %v", format)
	}

	if err := writer.Write(results); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}
	return nil
}

// Writer defines the result write operation
type Writer interface {
	Write(Results) error
}

// TableWriter implements Writer and output in tabular form
type TableWriter struct {
	Severities []dbTypes.Severity
	Output     io.Writer
	Light      bool
}

// Write writes the result on standard output
func (tw TableWriter) Write(results Results) error {
	for _, result := range results {
		tw.write(result)
	}
	return nil
}

// nolint: gocyclo
// TODO: refactror and fix cyclometic complexity
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

	var severities []string
	for _, sev := range tw.Severities {
		severities = append(severities, sev.String())
	}

	for _, severity := range dbTypes.SeverityNames {
		if !utils.StringInSlice(severity, severities) {
			continue
		}
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

// JSONWriter implements result Writer
type JSONWriter struct {
	Output io.Writer
}

// Write writes the results in JSON format
func (jw JSONWriter) Write(results Results) error {
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprint(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}
	return nil
}

// TemplateWriter write result in custom format defined by user's template
type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

// NewTemplateWriter is the factory method to return TemplateWriter object
func NewTemplateWriter(output io.Writer, outputTemplate string) (*TemplateWriter, error) {
	if strings.HasPrefix(outputTemplate, "@") {
		buf, err := ioutil.ReadFile(strings.TrimPrefix(outputTemplate, "@"))
		if err != nil {
			return nil, xerrors.Errorf("error retrieving template from path: %w", err)
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
		"endWithPeriod": func(input string) string {
			if !strings.HasSuffix(input, ".") {
				input += "."
			}
			return input
		},
		"toLower": func(input string) string {
			return strings.ToLower(input)
		},
		"escapeString": func(input string) string {
			return html.EscapeString(input)
		},
		"getEnv": func(key string) string {
			return os.Getenv(key)
		},
		"getCurrentTime": func() string {
			return Now().UTC().Format(time.RFC3339Nano)
		},
	}).Parse(outputTemplate)
	if err != nil {
		return nil, xerrors.Errorf("error parsing template: %w", err)
	}
	return &TemplateWriter{Output: output, Template: tmpl}, nil
}

// Write writes result
func (tw TemplateWriter) Write(results Results) error {
	err := tw.Template.Execute(tw.Output, results)
	if err != nil {
		return xerrors.Errorf("failed to write with template: %w", err)
	}
	return nil
}
