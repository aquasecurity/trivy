package table

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/exp/maps"
	"golang.org/x/term"

	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	severityCritical = "CRITICAL"
	severityHigh     = "HIGH"
	severityMedium   = "MEDIUM"
	severityLow      = "LOW"
)

var severityRankMap = map[string]int{
	dbTypes.SeverityCritical.String(): 0,
	dbTypes.SeverityHigh.String():     1,
	dbTypes.SeverityMedium.String():   2,
	dbTypes.SeverityLow.String():      3,
	dbTypes.SeverityUnknown.String():  4,
}

type MisconfRendererOption func(*misconfigRenderer)

type misconfigRenderer struct {
	w                  *bytes.Buffer
	result             types.Result
	severities         []dbTypes.Severity
	trace              bool
	includeNonFailures bool
	width              int
	ansi               bool
	enableGrouping     bool
}

func NewMisconfigRenderer(result types.Result, severities []dbTypes.Severity, opts ...MisconfRendererOption) *misconfigRenderer {
	width, _, err := term.GetSize(0)
	if err != nil || width == 0 {
		width = 40
	}

	r := &misconfigRenderer{
		w:          bytes.NewBuffer([]byte{}),
		result:     result,
		severities: severities,
		width:      width,
	}

	for _, opt := range opts {
		opt(r)
	}

	if !r.ansi {
		tml.DisableFormatting()
	}

	return r
}

func WithANSI(ansi bool) MisconfRendererOption {
	return func(r *misconfigRenderer) {
		r.ansi = ansi
	}
}

func WithTrace(trace bool) MisconfRendererOption {
	return func(r *misconfigRenderer) {
		r.trace = trace
	}
}

func WithIncludeNonFailures(include bool) MisconfRendererOption {
	return func(r *misconfigRenderer) {
		r.includeNonFailures = include
	}
}

func WithGroupingResults(grouping bool) MisconfRendererOption {
	return func(r *misconfigRenderer) {
		r.enableGrouping = grouping
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

	if r.enableGrouping {
		for _, group := range r.groupMisconfs(r.result.Misconfigurations) {
			r.renderGroup(group)
		}
	} else {
		for _, m := range r.result.Misconfigurations {
			r.renderSingle(m)
		}
	}

	// For debugging
	if r.trace {
		r.outputTrace()
	}
	return r.w.String()
}

func (r *misconfigRenderer) countSeverities() map[string]int {
	severityCount := make(map[string]int)
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
	tml.Fprintln(r.w, input)
}

func (r *misconfigRenderer) newline() {
	tml.Fprintln(r.w, "")
}

func (r *misconfigRenderer) printDoubleDivider() {
	r.printf("<dim>%s\r\n", strings.Repeat("═", r.width))
}

func (r *misconfigRenderer) printSingleDivider() {
	r.printf("<dim>%s\r\n", strings.Repeat("─", r.width))
}

func (r *misconfigRenderer) renderSingle(misconf types.DetectedMisconfiguration) {
	r.renderSummary(misconf, 0)
	r.renderCode(misconf.CauseMetadata)
	r.printf("\r\n\r\n")
}

func (r *misconfigRenderer) renderGroup(group groupedMisconfs) {
	first, rest := group.split()
	r.renderSummary(first, len(rest))
	r.renderCode(first.CauseMetadata)
	r.renderRestCauses(rest)
	r.printf("\r\n\r\n")
}

func (r *misconfigRenderer) renderSummary(misconf types.DetectedMisconfiguration, similar int) {

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
	r.printf("%s", misconf.Message)
	if r.enableGrouping && similar > 0 {
		msg := " <dim>(%d similar results)"
		if similar == 1 {
			msg = " <dim>(%d similar result)"
		}
		r.printf(msg, similar)
	}

	r.newline()
	r.printDoubleDivider()

	// description
	r.printf("<dim>%s\r\n", misconf.Description)

	// show link if we have one
	if misconf.PrimaryURL != "" {
		r.printf("\r\n<dim>See %s\r\n", misconf.PrimaryURL)
	}

	r.printSingleDivider()
}

func (r *misconfigRenderer) renderCode(causeMetadata ftypes.CauseMetadata) {
	// highlight code if we can...
	if lines := causeMetadata.Code.Lines; len(lines) > 0 {

		var lineInfo string
		if causeMetadata.StartLine > 0 {
			lineInfo = tml.Sprintf("<dim>:</dim><blue>%d", causeMetadata.StartLine)
			if causeMetadata.IsMultiLine() {
				lineInfo = tml.Sprintf("%s<blue>-%d", lineInfo, causeMetadata.EndLine)
			}
		}
		r.printf(" <blue>%s%s\r\n", r.result.Target, lineInfo)
		for i, occ := range causeMetadata.Occurrences {
			lineInfo := fmt.Sprintf("%d-%d", occ.Location.StartLine, occ.Location.EndLine)
			if occ.Location.StartLine >= occ.Location.EndLine {
				lineInfo = fmt.Sprintf("%d", occ.Location.StartLine)
			}

			r.printf(
				" %s<dim>via </dim><italic>%s<dim>:%s (%s)\n",
				strings.Repeat(" ", i+2),
				occ.Filename,
				lineInfo,
				occ.Resource,
			)
		}

		r.printSingleDivider()
		for i, line := range lines {
			switch {
			case line.Truncated:
				r.printf("<dim>%4s   ", strings.Repeat(".", len(fmt.Sprintf("%d", line.Number))))
			case line.IsCause:
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
			default:
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

func (r *misconfigRenderer) renderRestCauses(misconfs []types.DetectedMisconfiguration) {
	if len(misconfs) == 0 {
		return
	}
	r.printf("<white>The rest causes:</white>\r\n")
	for _, misconf := range misconfs {
		cause := misconf.CauseMetadata
		lineInfo := fmt.Sprintf("%d", cause.StartLine)
		if cause.IsMultiLine() {
			lineInfo = fmt.Sprintf("%d-%d", cause.StartLine, cause.EndLine)
		}
		r.printf(" - <dim>%s:%s\r\n", r.result.Target, lineInfo)
	}
	r.printSingleDivider()
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

func (r *misconfigRenderer) groupMisconfs(misconfs []types.DetectedMisconfiguration) []groupedMisconfs {
	if len(misconfs) == 0 {
		return nil
	}
	return groupMisconfsByResource(misconfs)
}

type groupedMisconfs []types.DetectedMisconfiguration

func (g *groupedMisconfs) first() types.DetectedMisconfiguration {
	return (*g)[0]
}

func (g *groupedMisconfs) split() (types.DetectedMisconfiguration, []types.DetectedMisconfiguration) {
	if len(*g) == 1 {
		return g.first(), nil
	}
	return g.first(), (*g)[1:]
}

func groupMisconfsByResource(misconfs []types.DetectedMisconfiguration) []groupedMisconfs {
	groupsMap := make(map[string]groupedMisconfs)
	var rest []groupedMisconfs

	for _, misconf := range misconfs {
		if len(misconf.CauseMetadata.Occurrences) == 0 {
			rest = append(rest, groupedMisconfs{misconf})
			continue
		}

		occurrence := findBlockOccurrence(misconf.CauseMetadata)
		if occurrence == nil {
			rest = append(rest, groupedMisconfs{misconf})
			continue
		}

		key := buildKey(misconf, *occurrence)
		groupsMap[key] = append(groupsMap[key], misconf)
	}
	return append(sortedValues(groupsMap), rest...)
}

func buildKey(misconf types.DetectedMisconfiguration, occurrence ftypes.Occurrence) string {
	severityRank := severityRankMap[misconf.Severity]
	return fmt.Sprintf("%d:%s:%s", severityRank, misconf.Status, misconf.AVDID)
}

func findBlockOccurrence(cause ftypes.CauseMetadata) *ftypes.Occurrence {
	for i, occurrence := range cause.Occurrences {
		// The last occurrence or occurrence before the module is a block
		if strings.HasPrefix(occurrence.Resource, "module.") {
			if i > 0 {
				return &cause.Occurrences[i-1]
			}
			return nil
		} else if i == len(cause.Occurrences)-1 {
			return &occurrence
		}
	}
	return nil
}

func sortedValues(m map[string]groupedMisconfs) []groupedMisconfs {
	keys := maps.Keys(m)
	sort.Strings(keys)

	res := make([]groupedMisconfs, 0, len(m))

	for _, key := range keys {
		res = append(res, m[key])
	}
	return res
}
