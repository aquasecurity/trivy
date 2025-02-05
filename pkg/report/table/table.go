package table

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/fatih/color"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
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
	Severities []dbTypes.Severity
	Output     io.Writer

	// Show dependency origin tree
	Tree bool

	// Show suppressed findings
	ShowSuppressed bool

	// For misconfigurations
	IncludeNonFailures bool
	Trace              bool

	// For licenses
	LicenseRiskThreshold int
	IgnoredLicenses      []string

	// We need to use the same renderers for all results, for the correct operation of logs, once functions, etc.
	renderers
}

type Renderer interface {
	Render(result types.Result)
	Flush() string
}

type renderers struct {
	vulnerabilityRenderer *vulnerabilityRenderer
	misconfigRenderer     *misconfigRenderer
	secretRenderer        *secretRenderer
	pkgLicenseRenderer    *pkgLicenseRenderer
	fileLicenseRenderer   *fileLicenseRenderer
}

func (tw *Writer) initRenderers() {
	tw.renderers = renderers{
		vulnerabilityRenderer: NewVulnerabilityRenderer(tw.isOutputToTerminal(), tw.Tree, tw.ShowSuppressed, tw.Severities),
		misconfigRenderer:     NewMisconfigRenderer(tw.Severities, tw.Trace, tw.IncludeNonFailures, tw.isOutputToTerminal()),
		secretRenderer:        NewSecretRenderer(tw.isOutputToTerminal(), tw.Severities),
		pkgLicenseRenderer:    NewPkgLicenseRenderer(tw.isOutputToTerminal(), tw.Severities),
		fileLicenseRenderer:   NewFileLicenseRenderer(tw.isOutputToTerminal(), tw.Severities),
	}
}

// Write writes the result on standard output
func (tw *Writer) Write(_ context.Context, report types.Report) error {
	tw.initRenderers()

	for _, result := range report.Results {
		// Not display a table of custom resources
		if result.Class == types.ClassCustom {
			continue
		}
		tw.render(result)
	}

	tw.flush()
	return nil
}

func (tw *Writer) flush() {
	_, _ = fmt.Fprint(tw.Output, tw.vulnerabilityRenderer.Flush())
	_, _ = fmt.Fprint(tw.Output, tw.misconfigRenderer.Flush())
	_, _ = fmt.Fprint(tw.Output, tw.secretRenderer.Flush())
	_, _ = fmt.Fprint(tw.Output, tw.pkgLicenseRenderer.Flush())
	_, _ = fmt.Fprint(tw.Output, tw.fileLicenseRenderer.Flush())
}

func (tw *Writer) render(result types.Result) {
	if result.IsEmpty() && result.Class != types.ClassOSPkg {
		return
	}

	switch {
	// vulnerability
	case result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg:
		tw.vulnerabilityRenderer.Render(result)
	// misconfiguration
	case result.Class == types.ClassConfig:
		tw.misconfigRenderer.Render(result)
	// secret
	case result.Class == types.ClassSecret:
		tw.secretRenderer.Render(result)
	// package license
	case result.Class == types.ClassLicense:
		tw.pkgLicenseRenderer.Render(result)
	// file license
	case result.Class == types.ClassLicenseFile:
		tw.fileLicenseRenderer.Render(result)
	default:
		return
	}
}

func (tw *Writer) isOutputToTerminal() bool {
	return IsOutputToTerminal(tw.Output)
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
