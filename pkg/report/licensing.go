package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/fatih/color"
	"github.com/liamg/tml"
	"golang.org/x/exp/slices"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type LicenseReportWriter struct {
	output             io.Writer
	isOutputToTerminal bool
	riskThreshold      int
	ignoredLicenses    []string
}

func New(output io.Writer, terminalOutput bool, riskThreshold int, ignoredLicenses []string) LicenseReportWriter {
	return LicenseReportWriter{
		output:             output,
		isOutputToTerminal: terminalOutput,
		riskThreshold:      riskThreshold,
		ignoredLicenses:    ignoredLicenses,
	}
}

type reportFinding struct {
	target                    string
	googleClassification      string
	googleClassificationIndex int
	licenseName               string
	licenseLink               string
}

func (w LicenseReportWriter) WriteLicenseReport(report types.Report) error {

	if err := w.writePackages(report); err != nil {
		return err
	}

	return w.writeLooseFiles(report)
}

func (w LicenseReportWriter) writePackages(report types.Report) error {
	var findings []reportFinding

	for _, r := range report.Results {
		if r.PackageLicense != nil {
			for _, finding := range r.PackageLicense.Findings {
				if finding.GoogleLicenseClassificationIndex > w.riskThreshold ||
					slices.Contains(w.ignoredLicenses, finding.License) {
					continue
				}
				findings = append(findings, reportFinding{
					target:                    finding.PackageName,
					googleClassification:      finding.GoogleLicenseClassification,
					googleClassificationIndex: finding.GoogleLicenseClassificationIndex,
					licenseName:               finding.License,
				})
			}
		}
	}

	if len(findings) > 0 {
		w.PrintTitle("Package License(s)")
		return w.writeFindings(findings, "Google Classification", "License", "Package Name")
	}

	return nil
}

func (w LicenseReportWriter) writeLooseFiles(report types.Report) error {
	var findings []reportFinding

	for _, r := range report.Results {
		for _, finding := range r.License.Findings {
			if finding.GoogleLicenseClassificationIndex > w.riskThreshold ||
				slices.Contains(w.ignoredLicenses, finding.License) {
				continue
			}
			findings = append(findings, reportFinding{
				target:                    r.Target,
				googleClassification:      finding.GoogleLicenseClassification,
				googleClassificationIndex: finding.GoogleLicenseClassificationIndex,
				licenseName:               finding.License,
				licenseLink:               finding.LicenseLink,
			})
		}
	}
	if len(findings) > 0 {
		w.PrintTitle("Loose File License(s)")
		return w.writeFindings(findings, "Google Classification", "License", "File Location")
	}
	return nil
}

func (w LicenseReportWriter) writeFindings(findings []reportFinding, headings ...string) error {
	if len(findings) == 0 {
		return nil
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].googleClassificationIndex == findings[j].googleClassificationIndex {
			if findings[i].licenseName == findings[j].licenseName {
				return findings[i].target < findings[j].target
			}
			return findings[i].licenseName < findings[j].licenseName
		}
		return findings[i].googleClassificationIndex < findings[j].googleClassificationIndex
	})

	tableWriter := table.New(w.output)
	if w.isOutputToTerminal { // use ansi output if we're not piping elsewhere
		tableWriter.SetHeaderStyle(table.StyleBold)
		tableWriter.SetLineStyle(table.StyleDim)
		tableWriter.SetColumnMaxWidth(90)
	}

	tableWriter.SetBorders(true)
	tableWriter.SetAutoMerge(true)
	tableWriter.SetRowLines(true)

	alignment := []table.Alignment{
		table.AlignLeft, table.AlignLeft, table.AlignLeft,
		table.AlignLeft, table.AlignLeft,
	}

	tableWriter.SetAlignment(alignment...)
	tableWriter.SetHeaderAlignment(alignment...)
	tableWriter.SetHeaders(headings...)

	for _, f := range findings {
		tableWriter.AddRow(colorizeLicenceClassification(strings.TrimSpace(f.googleClassification)),
			strings.TrimSpace(f.licenseName), strings.TrimSpace(f.target))
	}

	tableWriter.Render()

	return nil
}

func (w LicenseReportWriter) Println(a ...interface{}) {
	_, _ = fmt.Fprintln(w.output, a...)
}

func (w LicenseReportWriter) Printf(msg string, a ...interface{}) {
	_, _ = fmt.Fprintf(w.output, msg, a...)
}

func (w LicenseReportWriter) PrintTitle(title string) {
	_ = tml.Fprintf(w.output, "\n<underline><bold>%s</bold></underline>\n\n", title)

}

func colorizeLicenceClassification(classification string) string {
	switch classification {
	case "unknown":
		return color.New(color.FgHiRed).Sprintf("Non Standard")
	case "forbidden":
		return color.New(color.FgHiRed).Sprintf("Forbidden")
	case "restricted":
		return color.New(color.FgRed).Sprintf("Restricted")
	}
	return cases.Title(language.AmericanEnglish).String(classification)
}
