package table

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type secretRenderer struct {
	w          *bytes.Buffer
	severities []dbTypes.Severity
	width      int
	ansi       bool
}

func NewSecretRenderer(buf *bytes.Buffer, ansi bool, severities []dbTypes.Severity) *secretRenderer {
	width, _, err := term.GetSize(0)
	if err != nil || width == 0 {
		width = 40
	}
	if !ansi {
		tml.DisableFormatting()
	}
	return &secretRenderer{
		w:          buf,
		severities: severities,
		width:      width,
		ansi:       ansi,
	}
}

func (r *secretRenderer) Render(result types.Result) {
	// Trivy doesn't currently support showing suppressed secrets
	// So just skip this result
	if len(result.Secrets) == 0 {
		return
	}
	target := result.Target + " (secrets)"
	RenderTarget(r.w, target, r.ansi)

	severityCount := r.countSeverities(result.Secrets)
	total, summaries := summarize(r.severities, severityCount)

	r.printf("Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	for _, m := range result.Secrets {
		r.renderSingle(result.Target, m)
	}
	return
}

func (r *secretRenderer) countSeverities(secrets []types.DetectedSecret) map[string]int {
	severityCount := make(map[string]int)
	for _, secret := range secrets {
		severity := secret.Severity
		severityCount[severity]++
	}
	return severityCount
}

func (r *secretRenderer) printf(format string, args ...any) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

func (r *secretRenderer) printDoubleDivider() {
	r.printf("<dim>%s\r\n", strings.Repeat("═", r.width))
}

func (r *secretRenderer) printSingleDivider() {
	r.printf("<dim>%s\r\n", strings.Repeat("─", r.width))
}

func (r *secretRenderer) renderSingle(target string, secret types.DetectedSecret) {
	r.renderSummary(secret)
	r.renderCode(target, secret)
	r.printf("\r\n\r\n")
}

func (r *secretRenderer) renderSummary(secret types.DetectedSecret) {

	// severity
	switch secret.Severity {
	case severityCritical:
		r.printf("<red><bold>%s: ", secret.Severity)
	case severityHigh:
		r.printf("<red>%s: ", secret.Severity)
	case severityMedium:
		r.printf("<yellow>%s: ", secret.Severity)
	case severityLow:
		r.printf("%s: ", secret.Severity)
	default:
		r.printf("<blue>%s: ", secret.Severity)
	}

	// heading
	r.printf("%s (%s)\r\n", secret.Category, secret.RuleID)
	r.printDoubleDivider()

	// description
	r.printf("<dim>%s\r\n", secret.Title)

	r.printSingleDivider()
}

func (r *secretRenderer) renderCode(target string, secret types.DetectedSecret) {
	// highlight code if we can...
	if lines := secret.Code.Lines; len(lines) > 0 {

		var lineInfo string
		if secret.StartLine > 0 {
			lineInfo = tml.Sprintf("<dim>:</dim><blue>%d", secret.StartLine)
			if secret.EndLine > secret.StartLine {
				lineInfo = tml.Sprintf("%s<blue>-%d", lineInfo, secret.EndLine)
			}
		}

		var note string
		if c := secret.Layer.CreatedBy; c != "" {
			if len(c) > 40 {
				// Too long
				c = c[:40]
			}
			note = fmt.Sprintf(" (added by '%s')", c)
		} else if secret.Layer.DiffID != "" {
			note = fmt.Sprintf(" (added in layer '%s')", strings.TrimPrefix(secret.Layer.DiffID, "sha256:")[:12])
		}
		r.printf(" <blue>%s%s<magenta>%s\r\n", target, lineInfo, note)
		r.printSingleDivider()

		for i, line := range lines {
			switch {
			case line.Truncated:
				r.printf("<dim>%4s   ", strings.Repeat(".", len(strconv.Itoa(line.Number))))
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
