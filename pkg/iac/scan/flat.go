package scan

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
)

// TODO: This struct is not currently serialized to JSON,
// so JSON tags may be removed if unused.
type FlatResult struct {
	// TODO: The following fields are currently unused:
	// nolint: gocritic
	// Deprecated, RuleID, LongID, RuleSummary, Impact, RangeAnnotation
	Deprecated      bool               `json:"deprecated,omitempty"`
	RuleID          string             `json:"rule_id"`
	LongID          string             `json:"long_id"`
	RuleSummary     string             `json:"rule_description"`
	RuleProvider    providers.Provider `json:"rule_provider"`
	RuleService     string             `json:"rule_service"`
	Impact          string             `json:"impact"`
	Resolution      string             `json:"resolution"`
	Links           []string           `json:"links"`
	Description     string             `json:"description"`
	RangeAnnotation string             `json:"-"`
	Severity        severity.Severity  `json:"severity"`
	Status          Status             `json:"status"`
	Resource        string             `json:"resource"`
	Occurrences     []Occurrence       `json:"occurrences,omitempty"`
	Location        FlatRange          `json:"location"`
	RenderedCause   RenderedCause      `json:"rendered_cause"`
}

type FlatRange struct {
	Filename  string `json:"filename"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func (r Results) Flatten() []FlatResult {
	results := make([]FlatResult, 0, len(r))
	for _, original := range r {
		results = append(results, original.Flatten())
	}
	return results
}

func (r *Result) Flatten() FlatResult {
	rng := r.metadata.Range()

	resMetadata := r.metadata

	for resMetadata.Parent() != nil {
		resMetadata = *resMetadata.Parent()
	}

	return FlatResult{
		Deprecated:      r.rule.Deprecated,
		LongID:          r.Rule().CanonicalID(),
		RuleSummary:     r.rule.Summary,
		RuleProvider:    r.rule.Provider,
		RuleService:     r.rule.Service,
		Impact:          r.rule.Impact,
		Resolution:      r.rule.Resolution,
		Links:           r.rule.Links,
		Description:     r.Description(),
		RangeAnnotation: r.Annotation(),
		Severity:        r.rule.Severity,
		Status:          r.status,
		Resource:        resMetadata.Reference(),
		Occurrences:     r.Occurrences(),
		Location: FlatRange{
			Filename:  rng.GetFilename(),
			StartLine: rng.GetStartLine(),
			EndLine:   rng.GetEndLine(),
		},
		RenderedCause: r.renderedCause,
	}
}
