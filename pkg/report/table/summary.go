package table

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/tml"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

type Scanner interface {
	Header() string
	Alignment() table.Alignment

	// Count returns the number of findings, but -1 if the scanner is not applicable
	Count(result types.Result) int

	String() string // Required to show correct logs
}

func NewScanner(scanner types.Scanner) Scanner {
	switch scanner {
	case types.VulnerabilityScanner:
		return VulnerabilityScanner{}
	case types.MisconfigScanner:
		return MisconfigScanner{}
	case types.SecretScanner:
		return SecretScanner{}
	case types.LicenseScanner:
		return LicenseScanner{}
	}
	return nil
}

type scannerAlignment struct{}

func (s scannerAlignment) Alignment() table.Alignment {
	return table.AlignCenter
}

type VulnerabilityScanner struct{ scannerAlignment }

func (s VulnerabilityScanner) Header() string {
	return "Vulnerabilities"
}

func (s VulnerabilityScanner) Count(result types.Result) int {
	if result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg {
		return len(result.Vulnerabilities)
	}
	return -1
}

func (s VulnerabilityScanner) String() string {
	return string(types.VulnerabilityScanner)
}

type MisconfigScanner struct{ scannerAlignment }

func (s MisconfigScanner) Header() string {
	return "Misconfigurations"
}

func (s MisconfigScanner) Count(result types.Result) int {
	if result.Class == types.ClassConfig {
		return len(result.Misconfigurations)
	}
	return -1
}

func (s MisconfigScanner) String() string {
	return string(types.MisconfigScanner)
}

type SecretScanner struct{ scannerAlignment }

func (s SecretScanner) Header() string {
	return "Secrets"
}

func (s SecretScanner) Count(result types.Result) int {
	if result.Class == types.ClassSecret {
		return len(result.Secrets)
	}
	return -1
}

func (s SecretScanner) String() string {
	return string(types.SecretScanner)
}

type LicenseScanner struct{ scannerAlignment }

func (s LicenseScanner) Header() string {
	return "Licenses"
}

func (s LicenseScanner) Count(result types.Result) int {
	if result.Class == types.ClassLicense || result.Class == types.ClassLicenseFile {
		return len(result.Licenses)
	}
	return -1
}

func (s LicenseScanner) String() string {
	return string(types.LicenseScanner)
}

type summaryRenderer struct {
	w          *bytes.Buffer
	report     types.Report
	isTerminal bool
	scanners   []Scanner
}

func NewSummaryRenderer(report types.Report, isTerminal bool, scanners types.Scanners) (*summaryRenderer, error) {
	var ss []Scanner
	for _, scanner := range scanners {
		s := NewScanner(scanner)
		if lo.IsNil(s) {
			continue
		}
		ss = append(ss, s)
	}

	// It should be an impossible case.
	// But it is possible when Trivy is used as a library.
	if len(scanners) == 0 {
		return nil, xerrors.Errorf("unable to find scanners")
	}

	buf := bytes.NewBuffer([]byte{})
	if !isTerminal {
		tml.DisableFormatting()
	}
	return &summaryRenderer{
		w:          buf,
		report:     report,
		isTerminal: isTerminal,
		scanners:   ss,
	}, nil
}

func (r *summaryRenderer) Render() string {
	r.renderSummary()

	return r.w.String()
}

func (r *summaryRenderer) printf(format string, args ...any) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

func (r *summaryRenderer) renderSummary() {
	r.printf("\n<underline><bold>Report Summary</bold></underline>\n\n")

	t := newTableWriter(r.w, r.isTerminal)
	t.SetAutoMerge(false)
	t.SetColumnMaxWidth(80)

	headers := []string{
		"Target",
		"Type",
	}
	alignments := []table.Alignment{
		table.AlignLeft,
		table.AlignCenter,
	}
	for _, scanner := range r.scanners {
		headers = append(headers, scanner.Header())
		alignments = append(alignments, scanner.Alignment())
	}
	t.SetHeaders(headers...)
	t.SetAlignment(alignments...)

	for _, result := range splitAggregatedPackages(r.report.Results) {
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
		for _, scanner := range r.scanners {
			rows = append(rows, r.colorizeCount(scanner.Count(result)))
		}
		t.AddRows(rows)
	}

	if len(r.report.Results) == 0 {
		r.showEmptyResultsWarning()
		t.AddRows(slices.Repeat([]string{"-"}, len(r.scanners)+2))
	}

	t.Render()

	// Show legend
	r.printf("Legend:\n" +
		"- '-': Not scanned\n" +
		"- '0': Clean (no security findings detected)\n\n")

	return
}

// showEmptyResultsWarning shows WARN why the results array is empty based on the enabled scanners.
// We need to separate the vuln/misconfig and secret/license scanners,
// because the results array contains results without findings for vulns/misconfig only.
func (r *summaryRenderer) showEmptyResultsWarning() {
	resultByFiles := []Scanner{
		NewScanner(types.VulnerabilityScanner),
		NewScanner(types.MisconfigScanner),
	}
	resultByFindings := []Scanner{
		NewScanner(types.SecretScanner),
		NewScanner(types.LicenseScanner),
	}

	var warnStrings []string
	if scanners := lo.Intersect(resultByFiles, r.scanners); len(scanners) > 0 {
		warnStrings = append(warnStrings, fmt.Sprintf("Supported files for %s scanner(s) not found.",
			strings.Join(xstrings.ToStringSlice(scanners), "/")))
	}
	if scanners := lo.Intersect(resultByFindings, r.scanners); len(scanners) > 0 {
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
	// Save packages to display them in the table even if no vulnerabilities were found
	resultMap := lo.SliceToMap(result.Packages, func(pkg ftypes.Package) (string, *types.Result) {
		filePath := rootJarFromPath(pkg.FilePath)
		return filePath, &types.Result{
			Target: lo.Ternary(filePath != "", filePath, result.Target),
			Class:  result.Class,
			Type:   result.Type,
		}
	})
	for _, vuln := range result.Vulnerabilities {
		pkgPath := rootJarFromPath(vuln.PkgPath)
		resultMap[pkgPath].Vulnerabilities = append(resultMap[pkgPath].Vulnerabilities, vuln)
	}
	newResults := lo.Values(resultMap)
	sort.Slice(newResults, func(i, j int) bool {
		return newResults[i].Target < newResults[j].Target
	})
	return lo.FromSlicePtr(newResults)
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

func (r *summaryRenderer) colorizeCount(count int) string {
	if count < 0 {
		return "-"
	}
	sprintf := fmt.Sprintf
	if count != 0 && r.isTerminal {
		sprintf = color.New(color.FgHiRed).SprintfFunc()
	}
	return sprintf("%d", count)
}
