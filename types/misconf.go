package types

import (
	"fmt"
	"sort"
)

type Misconfiguration struct {
	FileType   string         `json:",omitempty"`
	FilePath   string         `json:",omitempty"`
	Successes  MisconfResults `json:",omitempty"`
	Warnings   MisconfResults `json:",omitempty"`
	Failures   MisconfResults `json:",omitempty"`
	Exceptions MisconfResults `json:",omitempty"`
	Layer      Layer          `json:",omitempty"`
}

type MisconfResult struct {
	Namespace      string `json:",omitempty"`
	Message        string `json:",omitempty"`
	PolicyMetadata `json:",omitempty"`
}

type MisconfResults []MisconfResult

type PolicyMetadata struct {
	ID       string `json:",omitempty"`
	Type     string `json:",omitempty"`
	Title    string `json:",omitempty"`
	Severity string `json:",omitempty"`
}

type PolicyInputOption struct {
	Combine   bool                  `mapstructure:"combine"`
	Selectors []PolicyInputSelector `mapstructure:"selector"`
}

type PolicyInputSelector struct {
	Type string `mapstructure:"type"`
}

func (r MisconfResults) Len() int {
	return len(r)
}

func (r MisconfResults) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r MisconfResults) Less(i, j int) bool {
	switch {
	case r[i].Type != r[j].Type:
		return r[i].Type < r[j].Type
	case r[i].ID != r[j].ID:
		return r[i].ID < r[j].ID
	case r[i].Severity != r[j].Severity:
		return r[i].Severity < r[j].Severity
	}
	return r[i].Message < r[j].Message
}

func ToMisconfigurations(misconfs map[string]Misconfiguration) []Misconfiguration {
	var results []Misconfiguration
	for _, misconf := range misconfs {
		// Remove duplicates
		misconf.Successes = uniqueResults(misconf.Successes)

		// Sort results
		sort.Sort(misconf.Successes)
		sort.Sort(misconf.Warnings)
		sort.Sort(misconf.Failures)
		sort.Sort(misconf.Exceptions)

		results = append(results, misconf)
	}

	// Sort misconfigurations
	sort.Slice(results, func(i, j int) bool {
		if results[i].FileType != results[j].FileType {
			return results[i].FileType < results[j].FileType
		}
		return results[i].FilePath < results[j].FilePath
	})

	return results
}

func uniqueResults(results []MisconfResult) []MisconfResult {
	uniq := map[string]MisconfResult{}
	for _, result := range results {
		key := fmt.Sprintf("%s::%s::%s", result.ID, result.Namespace, result.Message)
		uniq[key] = result
	}

	var uniqResults []MisconfResult
	for _, s := range uniq {
		uniqResults = append(uniqResults, s)
	}
	return uniqResults
}
