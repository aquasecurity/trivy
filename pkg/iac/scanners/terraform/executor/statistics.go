package executor

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

type StatisticsItem struct {
	RuleID          string   `json:"rule_id"`
	RuleDescription string   `json:"rule_description"`
	Links           []string `json:"links"`
	Count           int      `json:"count"`
}

type Statistics []StatisticsItem

type StatisticsResult struct {
	Result Statistics `json:"results"`
}

func SortStatistics(statistics Statistics) Statistics {
	sort.Slice(statistics, func(i, j int) bool {
		return statistics[i].Count > statistics[j].Count
	})
	return statistics
}

func (statistics Statistics) PrintStatisticsTable(format string, w io.Writer) error {
	// lovely is the default so we keep it like that
	if format != "lovely" && format != "markdown" && format != "json" {
		return fmt.Errorf("you must specify only lovely, markdown or json format with --run-statistics")
	}

	sorted := SortStatistics(statistics)

	if format == "json" {
		result := StatisticsResult{Result: sorted}
		val, err := json.MarshalIndent(result, "", "    ")
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintln(w, string(val))

		return nil
	}

	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"Rule ID", "Description", "Link", "Count"})
	table.SetRowLine(true)

	if format == "markdown" {
		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
	}

	for _, item := range sorted {
		table.Append([]string{item.RuleID,
			item.RuleDescription,
			strings.Join(item.Links, "\n"),
			strconv.Itoa(item.Count)})
	}

	table.Render()

	return nil
}

func AddStatisticsCount(statistics Statistics, result scan.Result) Statistics {
	for i, statistic := range statistics {
		if statistic.RuleID == result.Rule().LongID() {
			statistics[i].Count += 1
			return statistics
		}
	}
	statistics = append(statistics, StatisticsItem{
		RuleID:          result.Rule().LongID(),
		RuleDescription: result.Rule().Summary,
		Links:           result.Rule().Links,
		Count:           1,
	})

	return statistics
}
