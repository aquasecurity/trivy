package table

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/fatih/color"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/tml"

	"github.com/aquasecurity/table"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	SeverityColor = []func(a ...interface{}) string{
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

	// We have to show a message once about using the '-format json' subcommand to get the full pkgPath
	ShowMessageOnce *sync.Once

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
func (tw Writer) Write(report types.Report) error {
	for _, result := range report.Results {
		// Not display a table of custom resources
		if result.Class == types.ClassCustom {
			continue
		}
		tw.write(result)
	}
	return nil
}

func (tw Writer) write(result types.Result) {
	if result.IsEmpty() && result.Class != types.ClassOSPkg {
		return
	}

	var renderer Renderer
	switch {
	// vulnerability
	case result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg:
		renderer = NewVulnerabilityRenderer(result, tw.isOutputToTerminal(), tw.Tree, tw.Severities)
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

	if output != xio.NopCloser(os.Stdout) {
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
