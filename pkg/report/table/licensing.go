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
	result      types.Result
	isTerminal  bool
	severities  []dbTypes.Severity
	once        *sync.Once
}

func NewPkgLicenseRenderer(result types.Result, isTerminal bool, severities []dbTypes.Severity) pkgLicenseRenderer {
	buf := bytes.NewBuffer([]byte{})
	return pkgLicenseRenderer{
		w:           buf,
		tableWriter: newTableWriter(buf, isTerminal),
		result:      result,
		isTerminal:  isTerminal,
		severities:  severities,
		once:        new(sync.Once),
	}
}

func (r pkgLicenseRenderer) Render() string {
	r.setHeaders()
	r.setRows()

	total, summaries := summarize(r.severities, r.countSeverities())

	target := r.result.Target + " (license)"
	RenderTarget(r.w, target, r.isTerminal)
	r.printf("Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	r.tableWriter.Render()

	return r.w.String()
}

func (r pkgLicenseRenderer) setHeaders() {
	header := []string{"Package", "License", "Classification", "Severity"}
	r.tableWriter.SetHeaders(header...)
}

func (r pkgLicenseRenderer) setRows() {
	for _, l := range r.result.Licenses {
		var row []string
		if r.isTerminal {
			row = []string{
				l.PkgName, l.Name, colorizeLicenseCategory(l.Category), ColorizeSeverity(l.Severity, l.Severity),
			}
		} else {
			row = []string{
				l.PkgName, l.Name, string(l.Category), l.Severity,
			}
		}
		r.tableWriter.AddRow(row...)
	}
}

func (r pkgLicenseRenderer) countSeverities() map[string]int {
	severityCount := map[string]int{}
	for _, l := range r.result.Licenses {
		severityCount[l.Severity]++
	}
	return severityCount
}

func (r *pkgLicenseRenderer) printf(format string, args ...interface{}) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

type fileLicenseRenderer struct {
	w           *bytes.Buffer
	tableWriter *table.Table
	result      types.Result
	isTerminal  bool
	severities  []dbTypes.Severity
	once        *sync.Once
}

func NewFileLicenseRenderer(result types.Result, isTerminal bool, severities []dbTypes.Severity) fileLicenseRenderer {
	buf := bytes.NewBuffer([]byte{})
	return fileLicenseRenderer{
		w:           buf,
		tableWriter: newTableWriter(buf, isTerminal),
		result:      result,
		isTerminal:  isTerminal,
		severities:  severities,
		once:        new(sync.Once),
	}
}

func (r fileLicenseRenderer) Render() string {
	r.setHeaders()
	r.setRows()

	total, summaries := summarize(r.severities, r.countSeverities())

	target := r.result.Target + " (license)"
	RenderTarget(r.w, target, r.isTerminal)
	r.printf("Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	r.tableWriter.Render()

	return r.w.String()
}

func (r fileLicenseRenderer) setHeaders() {
	header := []string{"Classification", "Severity", "License", "File Location"}
	r.tableWriter.SetHeaders(header...)
}

func (r fileLicenseRenderer) setRows() {
	sort.Slice(r.result.Licenses, func(i, j int) bool {
		a := r.result.Licenses[i]
		b := r.result.Licenses[j]
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

	for _, l := range r.result.Licenses {
		var row []string
		if r.isTerminal {
			row = []string{
				colorizeLicenseCategory(l.Category), ColorizeSeverity(l.Severity, l.Severity), l.Name, l.FilePath,
			}
		} else {
			row = []string{
				string(l.Category), l.Severity, l.Name, l.FilePath,
			}
		}
		r.tableWriter.AddRow(row...)
	}
}

func (r fileLicenseRenderer) countSeverities() map[string]int {
	severityCount := map[string]int{}
	for _, l := range r.result.Licenses {
		severityCount[l.Severity]++
	}
	return severityCount
}

func (r *fileLicenseRenderer) printf(format string, args ...interface{}) {
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
