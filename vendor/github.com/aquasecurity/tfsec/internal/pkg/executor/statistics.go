package executor

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/olekukonko/tablewriter"
)

type StatisticsItem struct {
	RuleID          string
	RuleDescription string
	Links           []string
	Count           int
}

type Statistics []StatisticsItem

func SortStatistics(statistics Statistics) Statistics {
	sort.Slice(statistics, func(i, j int) bool {
		return statistics[i].Count > statistics[j].Count
	})
	return statistics
}

func (statistics Statistics) PrintStatisticsTable() {
	table := tablewriter.NewWriter(os.Stdout)
	statistics = SortStatistics(statistics)
	table.SetHeader([]string{"Rule ID", "Description", "Link", "Count"})
	table.SetRowLine(true)

	for _, item := range statistics {
		table.Append([]string{item.RuleID,
			item.RuleDescription,
			strings.Join(item.Links, "\n"),
			strconv.Itoa(item.Count)})
	}

	table.Render()
}

func AddStatisticsCount(statistics Statistics, result rules.Result) Statistics {
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
