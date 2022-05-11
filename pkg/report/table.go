package report

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/liamg/clinch/terminal"

	"github.com/liamg/tml"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/exp/slices"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// TableWriter implements Writer and output in tabular form
type TableWriter struct {
	Severities []dbTypes.Severity
	Output     io.Writer

	// We have to show a message once about using the '-format json' subcommand to get the full pkgPath
	ShowMessageOnce *sync.Once

	// For misconfigurations
	IncludeNonFailures bool
	Trace              bool
}

// Write writes the result on standard output
func (tw TableWriter) Write(report types.Report) error {
	for _, result := range report.Results {
		tw.write(result)
	}
	return nil
}

func (tw TableWriter) write(result types.Result) {
	table := tablewriter.NewWriter(tw.Output)

	misconfigBuffer := bytes.NewBuffer([]byte{})

	var severityCount map[string]int
	switch {
	case len(result.Vulnerabilities) != 0:
		severityCount = tw.writeVulnerabilities(table, result.Vulnerabilities)
	case len(result.Misconfigurations) != 0:
		severityCount = tw.writeMisconfigurations(misconfigBuffer, result.Target, result.Misconfigurations)
	case len(result.Secrets) != 0:
		severityCount = tw.writeSecrets(table, result.Secrets)
	}

	total, summaries := tw.summary(severityCount)

	target := result.Target
	if result.Class == types.ClassSecret {
		if len(result.Secrets) == 0 {
			return
		}
		target += " (secrets)"
	} else if result.Class != types.ClassOSPkg {
		target += fmt.Sprintf(" (%s)", result.Type)
	}

	fmt.Printf("\n%s\n", target)
	fmt.Println(strings.Repeat("=", len(target)))
	if result.Class == types.ClassConfig {
		// for misconfigurations
		summary := result.MisconfSummary
		fmt.Printf("Tests: %d (SUCCESSES: %d, FAILURES: %d, EXCEPTIONS: %d)\n",
			summary.Successes+summary.Failures+summary.Exceptions, summary.Successes, summary.Failures, summary.Exceptions)
		fmt.Printf("Failures: %d (%s)\n\n", total, strings.Join(summaries, ", "))
	} else {
		// for vulnerabilities and secrets
		fmt.Printf("Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))
	}

	if len(result.Vulnerabilities) > 0 || len(result.Secrets) > 0 {
		table.SetAutoMergeCells(true)
		table.SetRowLine(true)
		table.Render()
	}

	if len(result.Misconfigurations) > 0 {
		_, _ = fmt.Fprint(tw.Output, misconfigBuffer.String())
	}

	// For debugging
	if tw.Trace {
		tw.outputTrace(result)
	}

	return
}

func (tw TableWriter) summary(severityCount map[string]int) (int, []string) {
	var total int
	var severities []string
	for _, sev := range tw.Severities {
		severities = append(severities, sev.String())
	}

	var summaries []string
	for _, severity := range dbTypes.SeverityNames {
		if !slices.Contains(severities, severity) {
			continue
		}
		count := severityCount[severity]
		r := fmt.Sprintf("%s: %d", severity, count)
		summaries = append(summaries, r)
		total += count
	}

	return total, summaries
}

func (tw TableWriter) writeVulnerabilities(table *tablewriter.Table, vulns []types.DetectedVulnerability) map[string]int {
	header := []string{"Library", "Vulnerability ID", "Severity", "Installed Version", "Fixed Version", "Title"}
	table.SetHeader(header)
	severityCount := tw.setVulnerabilityRows(table, vulns)

	return severityCount
}

func (tw TableWriter) writeSecrets(table *tablewriter.Table, secrets []ftypes.SecretFinding) map[string]int {
	table.SetColWidth(80)

	alignment := []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT}
	header := []string{"Category", "Description", "Severity", "Line No", "Match"}

	table.SetColumnAlignment(alignment)
	table.SetHeader(header)
	severityCount := tw.setSecretRows(table, secrets)

	return severityCount
}

func (tw TableWriter) setVulnerabilityRows(table *tablewriter.Table, vulns []types.DetectedVulnerability) map[string]int {
	severityCount := map[string]int{}
	for _, v := range vulns {
		severityCount[v.Severity]++
		lib := v.PkgName
		if v.PkgPath != "" {
			fileName := filepath.Base(v.PkgPath)
			lib = fmt.Sprintf("%s (%s)", v.PkgName, fileName)
			tw.ShowMessageOnce.Do(func() {
				log.Logger.Infof("Table result includes only package filenames. Use '--format json' option to get the full path to the package file.")
			})
		}

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
			row = []string{lib, v.VulnerabilityID, dbTypes.ColorizeSeverity(v.Severity),
				v.InstalledVersion, v.FixedVersion, strings.TrimSpace(title)}
		} else {
			row = []string{lib, v.VulnerabilityID, v.Severity, v.InstalledVersion, v.FixedVersion, strings.TrimSpace(title)}
		}

		table.Append(row)
	}
	return severityCount
}

func (tw TableWriter) setSecretRows(table *tablewriter.Table, secrets []ftypes.SecretFinding) map[string]int {
	severityCount := map[string]int{}
	for _, secret := range secrets {
		severity := secret.Severity
		severityCount[severity]++
		if tw.Output == os.Stdout {
			severity = dbTypes.ColorizeSeverity(severity)
		}

		row := []string{string(secret.Category), secret.Title, severity,
			fmt.Sprint(secret.StartLine), // multi-line is not supported for now.
			secret.Match}

		table.Append(row)
	}
	return severityCount
}

func (tw TableWriter) outputTrace(result types.Result) {
	blue := color.New(color.FgBlue).SprintFunc()
	green := color.New(color.FgGreen).SprintfFunc()
	red := color.New(color.FgRed).SprintfFunc()

	for _, misconf := range result.Misconfigurations {
		if len(misconf.Traces) == 0 {
			continue
		}

		c := green
		if misconf.Status == types.StatusFailure {
			c = red
		}

		tw.Println(c("\nID: %s", misconf.ID))
		tw.Println(c("File: %s", result.Target))
		tw.Println(c("Namespace: %s", misconf.Namespace))
		tw.Println(c("Query: %s", misconf.Query))
		tw.Println(c("Message: %s", misconf.Message))
		for _, t := range misconf.Traces {
			tw.Println(blue("TRACE "), t)
		}
		tw.Println()
	}
}

func (tw TableWriter) Println(a ...interface{}) {
	_, _ = fmt.Fprintln(tw.Output, a...)
}

func (tw TableWriter) countMisconfigSeverities(misconfs []types.DetectedMisconfiguration) map[string]int {
	severityCount := map[string]int{}
	for _, misconf := range misconfs {
		if misconf.Status == types.StatusFailure {
			severityCount[misconf.Severity]++
		}
	}
	return severityCount
}

func (tw TableWriter) writeMisconfigurations(w io.Writer, target string, misconfs []types.DetectedMisconfiguration) map[string]int {
	for _, misconf := range misconfs {
		tw.writeMisconfiguration(w, target, misconf)
	}
	return tw.countMisconfigSeverities(misconfs)
}

func (tw TableWriter) writeMisconfiguration(w io.Writer, filename string, misconf types.DetectedMisconfiguration) {

	width, _ := terminal.Size()
	if width <= 0 {
		width = 40
	}
	_ = tml.Fprintf(w, "<dim>%s\n", strings.Repeat("═", width))

	// show pass/fail/exception unless we are only showing failures
	if tw.IncludeNonFailures {
		switch misconf.Status {
		case types.StatusPassed:
			_ = tml.Fprintf(w, "<green><bold>%s: ", misconf.Status)
		case types.StatusFailure:
			_ = tml.Fprintf(w, "<red><bold>%s: ", misconf.Status)
		case types.StatusException:
			_ = tml.Fprintf(w, "<yellow><bold>%s: ", misconf.Status)
		}
	}

	// severity
	switch misconf.Severity {
	case "CRITICAL":
		_ = tml.Fprintf(w, "<red><bold>%s: ", misconf.Severity)
	case "HIGH":
		_ = tml.Fprintf(w, "<red>%s: ", misconf.Severity)
	case "MEDIUM":
		_ = tml.Fprintf(w, "<yellow>%s: ", misconf.Severity)
	case "LOW":
		_ = tml.Fprintf(w, "%s: ", misconf.Severity)
	default:
		_ = tml.Fprintf(w, "<blue>%s: ", misconf.Severity)
	}

	// message + description
	_ = tml.Fprintf(w, "%s\n", misconf.Message)
	_ = tml.Fprintf(w, "<dim>%s\n", strings.Repeat("═", width))
	_ = tml.Fprintf(w, "<italic><dim>%s\n", misconf.Description)
	// show link if we have one
	if misconf.PrimaryURL != "" {
		_ = tml.Fprintf(w, "\n<italic><dim>See %s\n", misconf.PrimaryURL)
	}

	// highlight code if we can...
	if lines := misconf.CauseMetadata.Code.Lines; len(lines) > 0 {
		_ = tml.Fprintf(w, "<dim>%s\n", strings.Repeat("─", width))
		var lineInfo string
		if misconf.CauseMetadata.StartLine > 0 {
			lineInfo = tml.Sprintf("<dim>:</dim><blue>%d", misconf.CauseMetadata.StartLine)
			if misconf.CauseMetadata.EndLine > misconf.CauseMetadata.StartLine {
				lineInfo = tml.Sprintf("%s<blue>-%d", lineInfo, misconf.CauseMetadata.EndLine)
			}
		}
		_ = tml.Fprintf(w, " <blue>%s%s\n", filename, lineInfo)
		_ = tml.Fprintf(w, "<dim>%s\n", strings.Repeat("─", width))
		for i, line := range lines {
			if line.Truncated {
				_ = tml.Fprintf(w, "<dim>%4s   ", strings.Repeat(".", len(fmt.Sprintf("%d", line.Number))))
			} else if line.IsCause {
				_ = tml.Fprintf(w, "<red>%4d ", line.Number)
				switch {
				case (line.FirstCause && line.LastCause) || len(lines) == 1:
					_ = tml.Fprintf(w, "<red>[ ")
				case line.FirstCause || i == 0:
					_ = tml.Fprintf(w, "<red>┌ ")
				case line.LastCause || i == len(lines)-1:
					_ = tml.Fprintf(w, "<red>└ ")
				default:
					_ = tml.Fprintf(w, "<red>│ ")
				}
			} else {
				_ = tml.Fprintf(w, "<dim><italic>%4d   ", line.Number)
			}
			_ = tml.Fprintf(w, "%s\n", line.Highlighted)
		}
	}

	_ = tml.Fprintf(w, "<dim>%s\n\n", strings.Repeat("─", width))
}
