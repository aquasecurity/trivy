package table

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

var (
	SeverityColor = []func(a ...any) string{
		color.New(color.FgCyan).SprintFunc(),   // UNKNOWN
		color.New(color.FgBlue).SprintFunc(),   // LOW
		color.New(color.FgYellow).SprintFunc(), // MEDIUM
		color.New(color.FgHiRed).SprintFunc(),  // HIGH
		color.New(color.FgRed).SprintFunc(),    // CRITICAL
	}
)

// Writer implements Writer and output in tabular form
type Writer struct {
	Scanners   types.Scanners
	Severities []dbTypes.Severity
	Output     io.Writer

	// Show dependency origin tree
	Tree bool

	// Show suppressed findings
	ShowSuppressed bool

	// Hide summary table
	NoSummaryTable bool

	// For misconfigurations
	IncludeNonFailures bool
	Trace              bool

	// For licenses
	LicenseRiskThreshold int
	IgnoredLicenses      []string
}

type Renderer interface {
	Render() string
}

// Write writes the result on standard output
func (tw Writer) Write(_ context.Context, report types.Report) error {
	if !tw.isOutputToTerminal() {
		tml.DisableFormatting()
	}

	if !tw.NoSummaryTable {
		if err := tw.renderSummary(report); err != nil {
			return xerrors.Errorf("failed to render summary: %w", err)
		}
	}

	for _, result := range report.Results {
		// Not display a table of custom resources
		if result.Class == types.ClassCustom {
			continue
		}
		tw.write(result)
	}
	return nil
}

func (tw Writer) renderSummary(report types.Report) error {
	if len(report.Results) == 0 {
		tw.showEmptyResultsWarning()
		return nil
	}

	// Fprintln has a bug
	if err := tml.Fprintf(tw.Output, "\n<underline><bold>Report Summary</bold></underline>\n\n"); err != nil {
		return err
	}

	t := newTableWriter(tw.Output, tw.isOutputToTerminal())
	t.SetAutoMerge(false)
	t.SetColumnMaxWidth(80)

	var scanners []Scanner
	for _, scanner := range tw.Scanners {
		s := NewScanner(scanner)
		if lo.IsNil(s) {
			continue
		}
		scanners = append(scanners, s)
	}

	// It should be an impossible case.
	// But it is possible when Trivy is used as a library.
	if len(scanners) == 0 {
		return xerrors.Errorf("unable to find scanners")
	}

	headers := []string{
		"Target",
		"Type",
	}
	alignments := []table.Alignment{
		table.AlignLeft,
		table.AlignCenter,
	}
	for _, scanner := range scanners {
		headers = append(headers, scanner.Header())
		alignments = append(alignments, scanner.Alignment())
	}
	t.SetHeaders(headers...)
	t.SetAlignment(alignments...)

	for _, result := range splitAggregatedPackages(report.Results) {
		resultType := string(result.Type)
		if result.Class == types.ClassSecret {
			resultType = "text"
		} else if result.Class == types.ClassLicense || result.Class == types.ClassLicenseFile {
			resultType = "-"
		}
		rows := []string{
			result.Target,
			resultType,
		}
		for _, scanner := range scanners {
			rows = append(rows, tw.colorizeCount(scanner.Count(result)))
		}
		t.AddRows(rows)
	}
	t.Render()

	// Show legend
	if err := tml.Fprintf(tw.Output, "Legend:\n"+
		"- '-': Not scanned\n"+
		"- '0': Clean (no security findings detected)\n\n"); err != nil {
		return err
	}
	return nil
}

// showEmptyResultsWarning shows WARN why the results array is empty based on the enabled scanners.
// We need to separate the vuln/misconfig and secret/license scanners,
// because the results array contains results without findings for vulns/misconfig only.
func (tw Writer) showEmptyResultsWarning() {
	resultByFiles := []types.Scanner{
		types.VulnerabilityScanner,
		types.MisconfigScanner,
	}
	resultByFindings := []types.Scanner{
		types.SecretScanner,
		types.LicenseScanner,
	}

	var warnStrings []string
	if scanners := lo.Intersect(resultByFiles, tw.Scanners); len(scanners) > 0 {
		warnStrings = append(warnStrings, fmt.Sprintf("Supported files for %s scanner(s) not found.",
			strings.Join(xstrings.ToStringSlice(scanners), "/")))
	}
	if scanners := lo.Intersect(resultByFindings, tw.Scanners); len(scanners) > 0 {
		warnStrings = append(warnStrings, fmt.Sprintf("No results found for %s scanner(s).",
			strings.Join(xstrings.ToStringSlice(scanners), "/")))
	}

	if len(warnStrings) == 0 {
		warnStrings = append(warnStrings, "Scanners are not enabled.")
	}

	log.WithPrefix("report").Info(strings.Join(warnStrings, " "))
}

// splitAggregatedPackages splits aggregated packages into different results with path as target.
// Other results will be returned as is.
func splitAggregatedPackages(results types.Results) types.Results {
	var newResults types.Results

	for _, result := range results {
		if !slices.Contains(ftypes.AggregatingTypes, result.Type) &&
			// License results from applications don't have `Type`.
			(result.Class != types.ClassLicense || !slices.Contains(lo.Values(langpkg.PkgTargets), result.Target)) {
			newResults = append(newResults, result)
			continue
		}

		newResults = append(newResults, splitAggregatedVulns(result)...)
		newResults = append(newResults, splitAggregatedLicenses(result)...)

	}
	return newResults
}

func splitAggregatedVulns(result types.Result) types.Results {
	var newResults types.Results

	// Save packages to display them in the table even if no vulnerabilities were found
	vulns := lo.SliceToMap(result.Packages, func(pkg ftypes.Package) (string, []types.DetectedVulnerability) {
		return rootJarFromPath(pkg.FilePath), []types.DetectedVulnerability{}
	})

	for _, vuln := range result.Vulnerabilities {
		pkgPath := rootJarFromPath(vuln.PkgPath)
		vulns[pkgPath] = append(vulns[pkgPath], vuln)
	}
	for pkgPath, v := range vulns {
		newResult := result
		newResult.Target = lo.Ternary(pkgPath != "", pkgPath, result.Target)
		newResult.Vulnerabilities = v

		newResults = append(newResults, newResult)
	}

	sort.Slice(newResults, func(i, j int) bool {
		return newResults[i].Target < newResults[j].Target
	})
	return newResults
}

func splitAggregatedLicenses(result types.Result) types.Results {
	var newResults types.Results

	licenses := make(map[string][]types.DetectedLicense)
	for _, license := range result.Licenses {
		licenses[license.FilePath] = append(licenses[license.FilePath], license)
	}
	for filePath, l := range licenses {
		newResult := result
		newResult.Target = lo.Ternary(filePath != "", filePath, result.Target)
		newResult.Licenses = l

		newResults = append(newResults, newResult)
	}

	sort.Slice(newResults, func(i, j int) bool {
		return newResults[i].Target < newResults[j].Target
	})
	return newResults
}

func (tw Writer) write(result types.Result) {
	if result.IsEmpty() && result.Class != types.ClassOSPkg {
		return
	}

	var renderer Renderer
	switch {
	// vulnerability
	case result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg:
		renderer = NewVulnerabilityRenderer(result, tw.isOutputToTerminal(), tw.Tree, tw.ShowSuppressed, tw.Severities)
	// misconfiguration
	case result.Class == types.ClassConfig:
		renderer = NewMisconfigRenderer(result, tw.Severities, tw.Trace, tw.IncludeNonFailures, tw.isOutputToTerminal())
	// secret
	case result.Class == types.ClassSecret:
		renderer = NewSecretRenderer(result.Target, result.Secrets, tw.isOutputToTerminal(), tw.Severities)
	// package license
	case result.Class == types.ClassLicense:
		renderer = NewPkgLicenseRenderer(result, tw.isOutputToTerminal(), tw.Severities)
	// file license
	case result.Class == types.ClassLicenseFile:
		renderer = NewFileLicenseRenderer(result, tw.isOutputToTerminal(), tw.Severities)
	default:
		return
	}

	_, _ = fmt.Fprint(tw.Output, renderer.Render())
}

func (tw Writer) isOutputToTerminal() bool {
	return IsOutputToTerminal(tw.Output)
}

func (tw Writer) colorizeCount(count int) string {
	if count < 0 {
		return "-"
	}
	sprintf := fmt.Sprintf
	if count != 0 && tw.isOutputToTerminal() {
		sprintf = color.New(color.FgHiRed).SprintfFunc()
	}
	return sprintf("%d", count)
}

func newTableWriter(output io.Writer, isTerminal bool) *table.Table {
	tableWriter := table.New(output)
	if isTerminal { // use ansi output if we're not piping elsewhere
		tableWriter.SetHeaderStyle(table.StyleBold)
		tableWriter.SetLineStyle(table.StyleDim)
	}
	tableWriter.SetBorders(true)
	tableWriter.SetAutoMerge(true)
	tableWriter.SetRowLines(true)

	return tableWriter
}

func summarize(specifiedSeverities []dbTypes.Severity, severityCount map[string]int) (int, []string) {
	var total int
	var severities []string
	for _, sev := range specifiedSeverities {
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

func IsOutputToTerminal(output io.Writer) bool {
	if runtime.GOOS == "windows" {
		// if its windows, we don't support formatting
		return false
	}

	if output != os.Stdout {
		return false
	}
	o, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (o.Mode() & os.ModeCharDevice) == os.ModeCharDevice
}

func RenderTarget(w io.Writer, target string, isTerminal bool) {
	if isTerminal {
		// nolint
		_ = tml.Fprintf(w, "\n<underline><bold>%s</bold></underline>\n\n", target)
	} else {
		_, _ = fmt.Fprintf(w, "\n%s\n", target)
		_, _ = fmt.Fprintf(w, "%s\n", strings.Repeat("=", len(target)))
	}
}

func ColorizeSeverity(value, severity string) string {
	for i, name := range dbTypes.SeverityNames {
		if severity == name {
			return SeverityColor[i](value)
		}
	}
	return color.New(color.FgBlue).SprintFunc()(severity)
}
