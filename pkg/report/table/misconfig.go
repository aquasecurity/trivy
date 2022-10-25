package table

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/fatih/color"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/aquasecurity/tml"

	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	severityCritical = "CRITICAL"
	severityHigh     = "HIGH"
	severityMedium   = "MEDIUM"
	severityLow      = "LOW"
)

type misconfigRenderer struct {
	w                  *bytes.Buffer
	result             types.Result
	severities         []dbTypes.Severity
	trace              bool
	includeNonFailures bool
	width              int
	ansi               bool
}

func NewMisconfigRenderer(result types.Result, severities []dbTypes.Severity, trace, includeNonFailures bool, ansi bool) *misconfigRenderer {
	width, _, err := terminal.GetSize(0)
	if err != nil || width == 0 {
		width = 40
	}
	if !ansi {
		tml.DisableFormatting()
	}
	return &misconfigRenderer{
		w:                  bytes.NewBuffer([]byte{}),
		result:             result,
		severities:         severities,
		trace:              trace,
		includeNonFailures: includeNonFailures,
		width:              width,
		ansi:               ansi,
	}
}

func (r *misconfigRenderer) Render() string {
	target := fmt.Sprintf("%s (%s)", r.result.Target, r.result.Type)
	RenderTarget(r.w, target, r.ansi)

	total, summaries := summarize(r.severities, r.countSeverities())

	summary := r.result.MisconfSummary
	r.printf("Tests: %d (SUCCESSES: %d, FAILURES: %d, EXCEPTIONS: %d)\n",
		summary.Successes+summary.Failures+summary.Exceptions, summary.Successes, summary.Failures, summary.Exceptions)
	r.printf("Failures: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	for _, m := range r.result.Misconfigurations {
		r.renderSingle(m)
	}

	// For debugging
	if r.trace {
		r.outputTrace()
	}
	return r.w.String()
}

func (r *misconfigRenderer) countSeverities() map[string]int {
	severityCount := map[string]int{}
	for _, misconf := range r.result.Misconfigurations {
		if misconf.Status == types.StatusFailure {
			severityCount[misconf.Severity]++
		}
	}
	return severityCount
}

func (r *misconfigRenderer) printf(format string, args ...interface{}) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

func (r *misconfigRenderer) println(input string) {
	// nolint
	tml.Fprintln(r.w, input)
}

func (r *misconfigRenderer) printDoubleDivider() {
	r.printf("<dim>%s\r\n", strings.Repeat("═", r.width))
}

func (r *misconfigRenderer) printSingleDivider() {
	r.printf("<dim>%s\r\n", strings.Repeat("─", r.width))
}

func (r *misconfigRenderer) renderSingle(misconf types.DetectedMisconfiguration) {
	r.renderSummary(misconf)
	r.renderCode(misconf)
	r.printf("\r\n\r\n")
}

func (r *misconfigRenderer) renderSummary(misconf types.DetectedMisconfiguration) {

	// show pass/fail/exception unless we are only showing failures
	if r.includeNonFailures {
		switch misconf.Status {
		case types.StatusPassed:
			r.printf("<green><bold>%s: ", misconf.Status)
		case types.StatusFailure:
			r.printf("<red><bold>%s: ", misconf.Status)
		case types.StatusException:
			r.printf("<yellow><bold>%s: ", misconf.Status)
		}
	}

	// severity
	switch misconf.Severity {
	case severityCritical:
		r.printf("<red><bold>%s: ", misconf.Severity)
	case severityHigh:
		r.printf("<red>%s: ", misconf.Severity)
	case severityMedium:
		r.printf("<yellow>%s: ", misconf.Severity)
	case severityLow:
		r.printf("%s: ", misconf.Severity)
	default:
		r.printf("<blue>%s: ", misconf.Severity)
	}

	// heading
	r.printf("%s\r\n", misconf.Message)
	r.printDoubleDivider()

	// description
	r.printf("<dim>%s\r\n", misconf.Description)

	// show link if we have one
	if misconf.PrimaryURL != "" {
		r.printf("\r\n<dim>See %s\r\n", misconf.PrimaryURL)
	}

	r.printSingleDivider()
}

func (r *misconfigRenderer) renderCode(misconf types.DetectedMisconfiguration) {
	// highlight code if we can...
	if lines := misconf.CauseMetadata.Code.Lines; len(lines) > 0 {

		var lineInfo string
		if misconf.CauseMetadata.StartLine > 0 {
			lineInfo = tml.Sprintf("<dim>:</dim><blue>%d", misconf.CauseMetadata.StartLine)
			if misconf.CauseMetadata.EndLine > misconf.CauseMetadata.StartLine {
				lineInfo = tml.Sprintf("%s<blue>-%d", lineInfo, misconf.CauseMetadata.EndLine)
			}
		}
		r.printf(" <blue>%s%s\r\n", r.result.Target, lineInfo)
		r.printSingleDivider()
		for i, line := range lines {
			if line.Truncated {
				r.printf("<dim>%4s   ", strings.Repeat(".", len(fmt.Sprintf("%d", line.Number))))
			} else if line.IsCause {
				r.printf("<red>%4d ", line.Number)
				switch {
				case (line.FirstCause && line.LastCause) || len(lines) == 1:
					r.printf("<red>[ ")
				case line.FirstCause || i == 0:
					r.printf("<red>┌ ")
				case line.LastCause || i == len(lines)-1:
					r.printf("<red>└ ")
				default:
					r.printf("<red>│ ")
				}
			} else {
				r.printf("<dim>%4d   ", line.Number)
			}
			if r.ansi {
				r.printf("%s\r\n", line.Highlighted)
			} else {
				r.printf("%s\r\n", line.Content)
			}
		}
		r.printSingleDivider()
	}
}

func (r *misconfigRenderer) outputTrace() {
	blue := color.New(color.FgBlue).SprintFunc()
	green := color.New(color.FgGreen).SprintfFunc()
	red := color.New(color.FgRed).SprintfFunc()

	for _, misconf := range r.result.Misconfigurations {
		if len(misconf.Traces) == 0 {
			continue
		}

		c := green
		if misconf.Status == types.StatusFailure {
			c = red
		}

		r.println(c("\nID: %s", misconf.ID))
		r.println(c("File: %s", r.result.Target))
		r.println(c("Namespace: %s", misconf.Namespace))
		r.println(c("Query: %s", misconf.Query))
		r.println(c("Message: %s", misconf.Message))
		for _, t := range misconf.Traces {
			r.println(blue("TRACE ") + t)
		}
		r.println("")
	}
}
