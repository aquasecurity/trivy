package rules

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/defsec/parsers/types"
)

type Status uint8

const (
	StatusFailed Status = iota
	StatusPassed
)

type Result struct {
	rule             Rule
	description      string
	annotation       string
	status           Status
	metadata         types.Metadata
	severityOverride *severity.Severity
}

func (r Result) Severity() severity.Severity {
	if r.severityOverride != nil {
		return *r.severityOverride
	}
	return r.Rule().Severity
}

func (r *Result) OverrideSeverity(s severity.Severity) {
	r.severityOverride = &s
}

func (r *Result) OverrideDescription(description string) {
	r.description = description
}

func (r *Result) OverrideMetadata(metadata types.Metadata) {
	r.metadata = metadata
}

func (r *Result) OverrideAnnotation(annotation string) {
	r.annotation = annotation
}

func (r Result) Status() Status {
	return r.status
}

func (r Result) Rule() Rule {
	return r.rule
}

func (r Result) Description() string {
	return r.description
}

func (r Result) Annotation() string {
	return r.annotation
}

func (r Result) Metadata() types.Metadata {
	return r.metadata
}

func (r Result) Range() types.Range {
	return r.metadata.Range()
}

type Results []Result

type MetadataProvider interface {
	GetMetadata() types.Metadata
	GetRawValue() interface{}
}

func (r *Results) Add(description string, source MetadataProvider) {
	result := Result{
		description: description,
	}
	result.metadata = source.GetMetadata()
	if result.metadata.IsExplicit() {
		annotationStr := rawToString(source.GetRawValue())
		result.annotation = annotationStr
	}
	*r = append(*r, result)
}

func (r *Results) AddPassed(source MetadataProvider, descriptions ...string) {
	res := Result{
		description: strings.Join(descriptions, " "),
		status:      StatusPassed,
	}
	res.metadata = source.GetMetadata()
	*r = append(*r, res)
}

func (r *Results) SetRule(rule Rule) {
	for i := range *r {
		(*r)[i].rule = rule
	}
}

func rawToString(raw interface{}) string {
	if raw == nil {
		return ""
	}
	switch t := raw.(type) {
	case int:
		return fmt.Sprintf("%d", t)
	case bool:
		return fmt.Sprintf("%t", t)
	case float64:
		return fmt.Sprintf("%f", t)
	case string:
		return fmt.Sprintf("%q", t)
	case []string:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	case []int:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	case []float64:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	case []bool:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	default:
		return "?"
	}
}
