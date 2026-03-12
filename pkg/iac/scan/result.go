package scan

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Status uint8

const (
	StatusFailed Status = iota
	StatusPassed
	StatusIgnored
)

type Result struct {
	rule          Rule
	description   string
	annotation    string
	status        Status
	metadata      iacTypes.Metadata
	regoNamespace string
	regoRule      string
	traces        []string
	fsPath        string
	renderedCause RenderedCause
}

func (r Result) RegoNamespace() string {
	return r.regoNamespace
}

func (r Result) RegoRule() string {
	return r.regoRule
}

func (r *Result) OverrideMetadata(metadata iacTypes.Metadata) {
	r.metadata = metadata
}

func (r *Result) OverrideStatus(status Status) {
	r.status = status
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

func (r Result) Metadata() iacTypes.Metadata {
	return r.metadata
}

func (r Result) Range() iacTypes.Range {
	return r.metadata.Range()
}

func (r Result) Traces() []string {
	return r.traces
}

type RenderedCause struct {
	Raw string
}

func (r *Result) WithRenderedCause(cause RenderedCause) {
	r.renderedCause = cause
}

func (r *Result) AbsolutePath(fsRoot string, metadata iacTypes.Metadata) string {
	if strings.HasSuffix(fsRoot, ":") {
		fsRoot += "/"
	}

	if metadata.IsUnmanaged() {
		return ""
	}
	rng := metadata.Range()
	if rng.GetSourcePrefix() != "" && !strings.HasPrefix(rng.GetSourcePrefix(), ".") {
		return rng.GetFilename()
	}
	return filepath.Join(fsRoot, rng.GetLocalFilename())
}

func (r *Result) RelativePathTo(fsRoot, to string, metadata iacTypes.Metadata) string {

	absolute := r.AbsolutePath(fsRoot, metadata)

	if strings.HasSuffix(fsRoot, ":") {
		fsRoot += "/"
	}

	if metadata.IsUnmanaged() {
		return absolute
	}
	rng := metadata.Range()
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
	GetMetadata() iacTypes.Metadata
	GetRawValue() any
}

func (r *Results) GetPassed() Results {
	return r.byStatus(StatusPassed)
}

func (r *Results) GetIgnored() Results {
	return r.byStatus(StatusIgnored)
}

func (r *Results) GetFailed() Results {
	return r.byStatus(StatusFailed)
}

func (r *Results) byStatus(status Status) Results {
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

func (r *Results) AddRego(description, namespace, rule string, traces []string, source MetadataProvider) {
	result := Result{
		description:   description,
		regoNamespace: namespace,
		regoRule:      rule,
		traces:        traces,
	}
	result.metadata = getMetadataFromSource(source)
	if result.metadata.IsExplicit() {
		result.annotation = getAnnotation(source)
	}
	rnge := result.metadata.Range()
	result.fsPath = rnge.GetLocalFilename()
	*r = append(*r, result)
}

func getMetadataFromSource(source any) iacTypes.Metadata {
	if provider, ok := source.(MetadataProvider); ok {
		return provider.GetMetadata()
	}

	metaValue := reflect.ValueOf(source)
	if metaValue.Kind() == reflect.Ptr {
		metaValue = metaValue.Elem()
	}
	metaVal := metaValue.FieldByName("Metadata")
	return metaVal.Interface().(iacTypes.Metadata)
}

func getAnnotation(source any) string {
	if provider, ok := source.(MetadataProvider); ok {
		return rawToString(provider.GetRawValue())
	}
	return ""
}

func (r *Results) AddPassedRego(namespace, rule string, traces []string, source any) {
	res := Result{
		status:        StatusPassed,
		regoNamespace: namespace,
		regoRule:      rule,
		traces:        traces,
	}
	res.metadata = getMetadataFromSource(source)
	rnge := res.metadata.Range()
	res.fsPath = rnge.GetLocalFilename()
	*r = append(*r, res)
}

func (r *Results) Ignore(ignoreRules ignore.Rules, ignores map[string]ignore.Ignorer) {
	for i, result := range *r {
		allIDs := []string{
			result.Rule().ID,
			strings.ToLower(result.Rule().ID),
			result.Rule().CanonicalID(),
			result.Rule().AVDID,
			strings.ToLower(result.Rule().AVDID),
			result.Rule().ShortCode,
		}
		allIDs = append(allIDs, result.Rule().Aliases...)

		if ignoreRules.Ignore(result.Metadata(), allIDs, ignores) {
			(*r)[i].OverrideStatus(StatusIgnored)
		}
	}
}

func (r *Results) SetRule(rule Rule) {
	for i := range *r {
		res := &(*r)[i]
		res.rule = rule
	}
}

func (r *Results) SetSourceAndFilesystem(source string, f fs.FS, logicalSource bool) {
	for i := range *r {
		res := &(*r)[i]
		m := res.Metadata()

		if m.IsUnmanaged() {
			continue
		}
		rng := m.Range()
		var newrng iacTypes.Range
		if logicalSource {
			newrng = iacTypes.NewRangeWithLogicalSource(rng.GetLocalFilename(), rng.GetStartLine(), rng.GetEndLine(), source, f)
		} else {
			newrng = iacTypes.NewRange(rng.GetLocalFilename(), rng.GetStartLine(), rng.GetEndLine(), source, f)
		}
		parent := m.Parent()
		switch {
		case m.IsExplicit():
			m = iacTypes.NewExplicitMetadata(newrng, m.Reference())
		default:
			m = iacTypes.NewMetadata(newrng, m.Reference())
		}
		if parent != nil {
			m.SetParentPtr(parent)
		}
		res.OverrideMetadata(m)
	}
}

func rawToString(raw any) string {
	if raw == nil {
		return ""
	}
	switch t := raw.(type) {
	case int:
		return strconv.Itoa(t)
	case bool:
		return strconv.FormatBool(t)
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

type Occurrence struct {
	Resource  string `json:"resource"`
	Filename  string `json:"filename"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func (r *Result) Occurrences() []Occurrence {
	var occurrences []Occurrence

	mod := &r.metadata

	for {
		mod = mod.Parent()
		if mod == nil {
			break
		}
		rng := mod.Range()
		occurrences = append(occurrences, Occurrence{
			Resource:  mod.Reference(),
			Filename:  rng.GetFilename(),
			StartLine: rng.GetStartLine(),
			EndLine:   rng.GetEndLine(),
		})
	}
	return occurrences
}
