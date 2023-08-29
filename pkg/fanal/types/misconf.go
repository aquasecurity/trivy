package types

import (
	"fmt"
	"sort"

	"github.com/samber/lo"
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
	Query          string `json:",omitempty"`
	Message        string `json:",omitempty"`
	PolicyMetadata `json:",omitempty"`
	CauseMetadata  `json:",omitempty"`

	// For debugging
	Traces []string `json:",omitempty"`
}

type MisconfResults []MisconfResult

type CauseMetadata struct {
	Resource    string       `json:",omitempty"`
	Provider    string       `json:",omitempty"`
	Service     string       `json:",omitempty"`
	StartLine   int          `json:",omitempty"`
	EndLine     int          `json:",omitempty"`
	Code        Code         `json:",omitempty"`
	Occurrences []Occurrence `json:",omitempty"`
}

type Occurrence struct {
	Resource string `json:",omitempty"`
	Filename string `json:",omitempty"`
	Location Location
}

type Code struct {
	Lines []Line
}

type Line struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted,omitempty"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

type PolicyMetadata struct {
	ID                 string   `json:",omitempty"`
	AVDID              string   `json:",omitempty"`
	Type               string   `json:",omitempty"`
	Title              string   `json:",omitempty"`
	Description        string   `json:",omitempty"`
	Severity           string   `json:",omitempty"`
	RecommendedActions string   `json:",omitempty" mapstructure:"recommended_actions"`
	References         []string `json:",omitempty"`
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
	case r[i].AVDID != r[j].AVDID:
		return r[i].AVDID < r[j].AVDID
	case r[i].ID != r[j].ID:
		return r[i].ID < r[j].ID
	case r[i].Severity != r[j].Severity:
		return r[i].Severity < r[j].Severity
	case r[i].Resource != r[j].Resource:
		return r[i].Resource < r[j].Resource
	}
	return r[i].Message < r[j].Message
}

func ToMisconfigurations(misconfs map[string]Misconfiguration) []Misconfiguration {
	var results []Misconfiguration
	for _, misconf := range misconfs {
		// Remove duplicates
		misconf.Successes = uniqueResults(misconf.Successes)
		misconf.Warnings = uniqueResults(misconf.Warnings)
		misconf.Failures = uniqueResults(misconf.Failures)

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
	if len(results) == 0 {
		return results
	}
	return lo.UniqBy(results, func(result MisconfResult) string {
		return fmt.Sprintf("ID: %s, Namespace: %s, Messsage: %s, Cause: %v",
			result.ID, result.Namespace, result.Message, result.CauseMetadata)
	})
}
