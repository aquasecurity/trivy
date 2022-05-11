package scan

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/severity"
)

type Status uint8

const (
	StatusFailed Status = iota
	StatusPassed
	StatusIgnored
)

type Result struct {
	rule             Rule
	description      string
	annotation       string
	status           Status
	metadata         types.Metadata
	severityOverride *severity.Severity
	regoNamespace    string
	regoRule         string
	warning          bool
	traces           []string
	fsPath           string
}

func (r Result) RegoNamespace() string {
	return r.regoNamespace
}

func (r Result) RegoRule() string {
	return r.regoRule
}

func (r Result) Severity() severity.Severity {
	if r.severityOverride != nil {
		return *r.severityOverride
	}
	return r.Rule().Severity
}

func (r *Result) IsWarning() bool {
	return r.warning
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

func (r *Result) OverrideStatus(status Status) {
	r.status = status
}

func (r *Result) OverrideAnnotation(annotation string) {
	r.annotation = annotation
}

func (r *Result) SetRule(ru Rule) {
	r.rule = ru
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

func (r Result) Traces() []string {
	return r.traces
}

func (r *Result) AbsolutePath(fsRoot string) string {
	if strings.HasSuffix(fsRoot, ":") {
		fsRoot += "/"
	}

	m := r.Metadata()
	if m.IsUnmanaged() || m.Range() == nil {
		return ""
	}
	rng := m.Range()
	if rng.GetSourcePrefix() != "" && !strings.HasPrefix(rng.GetSourcePrefix(), ".") {
		return rng.GetFilename()
	}
	return filepath.Join(fsRoot, rng.GetLocalFilename())
}

func (r *Result) RelativePathTo(fsRoot string, to string) string {

	absolute := r.AbsolutePath(fsRoot)

	if strings.HasSuffix(fsRoot, ":") {
		fsRoot += "/"
	}

	m := r.Metadata()
	if m.IsUnmanaged() || m.Range() == nil {
		return absolute
	}
	rng := m.Range()
	if rng.GetSourcePrefix() != "" && !strings.HasPrefix(rng.GetSourcePrefix(), ".") {
		return absolute
	}
	if !strings.HasPrefix(rng.GetLocalFilename(), strings.TrimSuffix(fsRoot, "/")) {
		return absolute
	}
	relative, err := filepath.Rel(to, rng.GetLocalFilename())
	if err != nil {
		return absolute
	}
	return relative
}

type Results []Result

type MetadataProvider interface {
	GetMetadata() types.Metadata
	GetRawValue() interface{}
}

func (r *Results) GetPassed() Results {
	return r.filterStatus(StatusPassed)
}

func (r *Results) GetIgnored() Results {
	return r.filterStatus(StatusIgnored)
}

func (r *Results) GetFailed() Results {
	return r.filterStatus(StatusFailed)
}

func (r *Results) filterStatus(status Status) Results {
	var filtered Results
	if r == nil {
		return filtered
	}
	for _, res := range *r {
		if res.Status() == status {
			filtered = append(filtered, res)
		}
	}
	return filtered
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
	rnge := result.metadata.Range()
	result.fsPath = rnge.GetLocalFilename()
	*r = append(*r, result)
}

func (r *Results) AddRego(description string, namespace string, rule string, traces []string, source MetadataProvider) {
	result := Result{
		description:   description,
		regoNamespace: namespace,
		regoRule:      rule,
		warning:       rule == "warn" || strings.HasPrefix(rule, "warn_"),
		traces:        traces,
	}
	result.metadata = source.GetMetadata()
	if result.metadata.IsExplicit() {
		annotationStr := rawToString(source.GetRawValue())
		result.annotation = annotationStr
	}
	rnge := result.metadata.Range()
	result.fsPath = rnge.GetLocalFilename()
	*r = append(*r, result)
}

func (r *Results) AddPassed(source MetadataProvider, descriptions ...string) {
	res := Result{
		description: strings.Join(descriptions, " "),
		status:      StatusPassed,
	}
	res.metadata = source.GetMetadata()
	rnge := res.metadata.Range()
	res.fsPath = rnge.GetLocalFilename()
	*r = append(*r, res)
}

func (r *Results) AddPassedRego(namespace string, rule string, traces []string, source MetadataProvider) {
	res := Result{
		status:        StatusPassed,
		regoNamespace: namespace,
		regoRule:      rule,
		traces:        traces,
	}
	res.metadata = source.GetMetadata()
	rnge := res.metadata.Range()
	res.fsPath = rnge.GetLocalFilename()
	*r = append(*r, res)
}

func (r *Results) AddIgnored(source MetadataProvider, descriptions ...string) {
	res := Result{
		description: strings.Join(descriptions, " "),
		status:      StatusIgnored,
	}
	res.metadata = source.GetMetadata()
	rnge := res.metadata.Range()
	res.fsPath = rnge.GetLocalFilename()
	*r = append(*r, res)
}

func (r *Results) SetRule(rule Rule) {
	for i := range *r {
		(*r)[i].rule = rule
	}
}

func (r *Results) SetSourceAndFilesystem(source string, f fs.FS) {
	for i := range *r {
		m := (*r)[i].Metadata()
		if m.IsUnmanaged() || m.Range() == nil {
			continue
		}
		rng := m.Range()
		newrng := types.NewRange(rng.GetLocalFilename(), rng.GetStartLine(), rng.GetEndLine(), source, f)
		switch {
		case m.IsExplicit():
			m = types.NewExplicitMetadata(newrng, m.Reference())
		default:
			m = types.NewMetadata(newrng, m.Reference())
		}
		(*r)[i].OverrideMetadata(m)
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
