package k8s

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aquasecurity/table"

	"github.com/liamg/tml"
)

var severityOrder = []string{"critical", "high", "medium", "low", "unknown"}

var severityColors = map[string]string{
	"critical": "<bold><red>Critical</red></bold>",
	"high":     "<red>High</red>",
	"medium":   "<yellow>Medium</yellow>",
	"low":      "Low",
	"unknown":  "<blue>Unknown</blue>",
}

type SummaryWriter struct {
	Output io.Writer
}

// Write writes the results in a summarized table format
func (s SummaryWriter) Write(report Report) error {
	consolidated := report.consolidate()
	_, _ = fmt.Fprintln(s.Output)
	_, _ = fmt.Fprintf(s.Output, "Summary Report for %s\n", consolidated.ClusterName)

	t := table.New(s.Output)
	t.SetHeaders("Namespace", "Resource", "Vulnerabilities", "Misconfigurations")

	sort.Slice(consolidated.Findings, func(i, j int) bool {
		return consolidated.Findings[i].Namespace > consolidated.Findings[j].Namespace
	})

	for _, finding := range consolidated.Findings {
		if !finding.Results.Failed() {
			continue
		}
		vCount := make(map[string]int)
		mCount := make(map[string]int)
		for _, r := range finding.Results {
			for _, rv := range r.Vulnerabilities {
				sev := strings.ToLower(rv.Severity)
				vCount[sev] = vCount[sev] + 1
			}
			for _, rv := range r.Misconfigurations {
				sev := strings.ToLower(rv.Severity)
				mCount[sev] = mCount[sev] + 1
			}
		}

		name := fmt.Sprintf("%s/%s", finding.Kind, finding.Name)
		vSummary := generateSummary(vCount, finding.Error, "No vulnerabilities found")
		mSummary := generateSummary(mCount, finding.Error, "No misconfigurations found")

		t.AddRow(finding.Namespace, name, vSummary, mSummary)
	}

	t.Render()
	return nil
}

func generateSummary(sevCount map[string]int, errorMessage, emptyMessage string) string {
	if errorMessage != "" {
		return errorMessage
	}
	var parts []string
	for _, sev := range severityOrder {
		if count, ok := sevCount[sev]; ok && count > 0 {
			col, ok := severityColors[sev]
			if !ok {
				col = strings.Title(sev)
			}
			parts = append(parts, tml.Sprintf(col+": %d", count))
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, ", ")
	}
	return emptyMessage
}
