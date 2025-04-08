package table

import (
	"bytes"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type pkgLicenseRenderer struct {
	w           *bytes.Buffer
	tableWriter *table.Table
	isTerminal  bool
	severities  []dbTypes.Severity
	once        *sync.Once
}

func NewPkgLicenseRenderer(buf *bytes.Buffer, isTerminal bool, severities []dbTypes.Severity) *pkgLicenseRenderer {
	return &pkgLicenseRenderer{
		w:           buf,
		tableWriter: newTableWriter(buf, isTerminal),
		isTerminal:  isTerminal,
		severities:  severities,
		once:        new(sync.Once),
	}
}

func (r *pkgLicenseRenderer) Render(result types.Result) {
	// Trivy doesn't currently support showing suppressed licenses
	// So just skip this result
	if len(result.Licenses) == 0 {
		return
	}

	r.setHeaders()
	r.setRows(result.Licenses)

	total, summaries := summarize(r.severities, r.countSeverities(result.Licenses))

	target := result.Target + " (license)"
	RenderTarget(r.w, target, r.isTerminal)
	r.printf("Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	r.tableWriter.Render()

	return
}

func (r *pkgLicenseRenderer) setHeaders() {
	header := []string{
		"Package",
		"License",
		"Classification",
		"Severity",
	}
	r.tableWriter.SetHeaders(header...)
}

func (r *pkgLicenseRenderer) setRows(licenses []types.DetectedLicense) {
	for _, l := range licenses {
		var row []string
		if r.isTerminal {
			row = []string{
				l.PkgName,
				l.Name,
				colorizeLicenseCategory(l.Category),
				ColorizeSeverity(l.Severity, l.Severity),
			}
		} else {
			row = []string{
				l.PkgName,
				l.Name,
				string(l.Category),
				l.Severity,
			}
		}
		r.tableWriter.AddRow(row...)
	}
}

func (r *pkgLicenseRenderer) countSeverities(licenses []types.DetectedLicense) map[string]int {
	severityCount := make(map[string]int)
	for _, l := range licenses {
		severityCount[l.Severity]++
	}
	return severityCount
}

func (r *pkgLicenseRenderer) printf(format string, args ...any) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

type fileLicenseRenderer struct {
	w           *bytes.Buffer
	tableWriter *table.Table
	isTerminal  bool
	severities  []dbTypes.Severity
	once        *sync.Once
}

func NewFileLicenseRenderer(buf *bytes.Buffer, isTerminal bool, severities []dbTypes.Severity) *fileLicenseRenderer {
	return &fileLicenseRenderer{
		w:           buf,
		tableWriter: newTableWriter(buf, isTerminal),
		isTerminal:  isTerminal,
		severities:  severities,
		once:        new(sync.Once),
	}
}

func (r *fileLicenseRenderer) Render(result types.Result) {
	// Trivy doesn't currently support showing suppressed licenses
	// So just skip this result
	if len(result.Licenses) == 0 {
		return
	}

	r.setHeaders()
	r.setRows(result.Licenses)

	total, summaries := summarize(r.severities, r.countSeverities(result.Licenses))

	target := result.Target + " (license)"
	RenderTarget(r.w, target, r.isTerminal)
	r.printf("Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	r.tableWriter.Render()

	return
}

func (r *fileLicenseRenderer) setHeaders() {
	header := []string{
		"Classification",
		"Severity",
		"License",
		"File Location",
	}
	r.tableWriter.SetHeaders(header...)
}

func (r *fileLicenseRenderer) setRows(licenses []types.DetectedLicense) {
	sort.Slice(licenses, func(i, j int) bool {
		a := licenses[i]
		b := licenses[j]
		if a.Severity != b.Severity {
			return 0 < dbTypes.CompareSeverityString(b.Severity, a.Severity)
		}
		if a.Category != b.Category {
			return a.Category > b.Category
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.FilePath < b.FilePath
	})

	for _, l := range licenses {
		var row []string
		if r.isTerminal {
			row = []string{
				colorizeLicenseCategory(l.Category),
				ColorizeSeverity(l.Severity, l.Severity),
				l.Name,
				l.FilePath,
			}
		} else {
			row = []string{
				string(l.Category),
				l.Severity,
				l.Name,
				l.FilePath,
			}
		}
		r.tableWriter.AddRow(row...)
	}
}

func (r *fileLicenseRenderer) countSeverities(licenses []types.DetectedLicense) map[string]int {
	severityCount := make(map[string]int)
	for _, l := range licenses {
		severityCount[l.Severity]++
	}
	return severityCount
}

func (r *fileLicenseRenderer) printf(format string, args ...any) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

func colorizeLicenseCategory(category ftypes.LicenseCategory) string {
	switch category {
	case ftypes.CategoryForbidden:
		return color.New(color.FgRed).Sprintf("Forbidden")
	case ftypes.CategoryRestricted:
		return color.New(color.FgHiRed).Sprintf("Restricted")
	case ftypes.CategoryUnknown:
		return color.New(color.FgCyan).Sprintf("Non Standard")
	}
	return cases.Title(language.AmericanEnglish).String(string(category))
}
