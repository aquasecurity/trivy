package sarif

import (
	"fmt"
)

// RunOption ...
type RunOption int

// IncludeEmptyResults ...
const IncludeEmptyResults RunOption = iota

// Run type represents a run of a tool
type Run struct {
	Tool                           Tool                            `json:"tool"`
	Artifacts                      []*Artifact                     `json:"artifacts,omitempty"`
	Invocations                    []*Invocation                   `json:"invocations,omitempty"`
	LogicalLocations               []*LogicalLocation              `json:"logicalLocations,omitempty"`
	Results                        []*Result                       `json:"results"`
	Addresses                      []*Address                      `json:"addresses,omitempty"`
	AutomationDetails              *RunAutomationDetails           `json:"automationDetails,omitempty"`
	BaselineGUID                   *string                         `json:"baselineGuid,omitempty"`
	ColumnKind                     interface{}                     `json:"columnKind,omitempty"`
	Conversion                     *Conversion                     `json:"conversion,omitempty"`
	DefaultEncoding                *string                         `json:"defaultEncoding,omitempty"`
	DefaultSourceLanguage          *string                         `json:"defaultSourceLanguage,omitempty"`
	ExternalPropertyFileReferences *ExternalPropertyFileReferences `json:"externalPropertyFileReferences,omitempty"`
	Graphs                         []*Graph                        `json:"graphs,omitempty"`
	Language                       *string                         `json:"language,omitempty"`
	NewlineSequences               []string                        `json:"newlineSequences,omitempty"`
	OriginalUriBaseIDs             map[string]*ArtifactLocation    `json:"originalUriBaseIds,omitempty"`
	Policies                       []*ToolComponent                `json:"policies,omitempty"`
	RedactionTokens                []string                        `json:"redactionTokens,omitempty"`
	RunAggregates                  []*RunAutomationDetails         `json:"runAggregates,omitempty"`
	SpecialLocations               *SpecialLocations               `json:"specialLocations,omitempty"`
	Taxonomies                     []*ToolComponent                `json:"taxonomies,omitempty"`
	ThreadFlowLocations            []*ThreadFlowLocation           `json:"threadFlowLocations,omitempty"`
	Translations                   []*ToolComponent                `json:"translations,omitempty"`
	VersionControlProvenance       []*VersionControlDetails        `json:"versionControlProvenance,omitempty"`
	WebRequests                    []*WebRequest                   `json:"webRequests,omitempty"`
	WebResponses                   []*WebResponse                  `json:"webResponses,omitempty"`
	PropertyBag
}

// NewRun creates a new Run and returns a pointer to it
func NewRun(tool Tool) *Run {
	return &Run{
		Tool:    tool,
		Results: []*Result{},
	}
}

// NewRunWithInformationURI creates a new Run and returns a pointer to it
func NewRunWithInformationURI(toolName, informationURI string) *Run {
	run := &Run{
		Tool: Tool{
			Driver: &ToolComponent{
				Name:           toolName,
				InformationURI: &informationURI,
				Rules: []*ReportingDescriptor{},
			},
		},
		Results: []*Result{},
	}

	return run
}

// WithResults sets the Results
func (run *Run) WithResults(results []*Result) *Run {
	for _, result := range results {
		run.AddResult(result)
	}
	return run
}

// AddResult ...
func (run *Run) AddResult(result *Result) {
	result = result.WithRuleIndex(run.Tool.Driver.getRuleIndex(result.RuleID))
	run.Results = append(run.Results, result)
}

// WithAddresses sets the Addresses
func (run *Run) WithAddresses(addresses []*Address) *Run {
	run.Addresses = addresses
	return run
}

// WithArtifacts sets the Artifacts
func (run *Run) WithArtifacts(artifacts []*Artifact) *Run {
	run.Artifacts = artifacts
	return run
}

// WithAutomationDetails sets the AutomationDetails
func (run *Run) WithAutomationDetails(automationDetails *RunAutomationDetails) *Run {
	run.AutomationDetails = automationDetails
	return run
}

// WithBaselineGUID sets the BaselineGUID
func (run *Run) WithBaselineGUID(baselineGUID string) *Run {
	run.BaselineGUID = &baselineGUID
	return run
}

// WithColumnKind sets the ColumnKind
func (run *Run) WithColumnKind(columnKind interface{}) *Run {
	run.ColumnKind = columnKind
	return run
}

// WithConversion sets the Conversion
func (run *Run) WithConversion(conversion *Conversion) *Run {
	run.Conversion = conversion
	return run
}

// WithDefaultEncoding sets the DefaultEncoding
func (run *Run) WithDefaultEncoding(defaultEncoding string) *Run {
	run.DefaultEncoding = &defaultEncoding
	return run
}

// WithDefaultSourceLanguage sets the DefaultSourceLanguage
func (run *Run) WithDefaultSourceLanguage(defaultSourceLangauge string) *Run {
	run.DefaultSourceLanguage = &defaultSourceLangauge
	return run
}

// WithExternalPropertyFileReferences sets the ExternalPropertyFileReferences
func (run *Run) WithExternalPropertyFileReferences(references *ExternalPropertyFileReferences) *Run {
	run.ExternalPropertyFileReferences = references
	return run
}

// WithGraphs sets the Graphs
func (run *Run) WithGraphs(graphs []*Graph) *Run {
	run.Graphs = graphs
	return run
}

// AddGraph ...
func (run *Run) AddGraph(graph *Graph) {
	run.Graphs = append(run.Graphs, graph)
}

// WithInvocations sets the Invocations
func (run *Run) WithInvocations(invocations []*Invocation) *Run {
	run.Invocations = invocations
	return run
}

// AddInvocations ...
func (run *Run) AddInvocations(invocation *Invocation) {
	run.Invocations = append(run.Invocations, invocation)
}

// WithLanguage sets the Language
func (run *Run) WithLanguage(language string) *Run {
	run.Language = &language
	return run
}

// WithLogicalLocations sets the LogicalLocations
func (run *Run) WithLogicalLocations(locations []*LogicalLocation) *Run {
	run.LogicalLocations = locations
	return run
}

// AddILogicalLocation ...
func (run *Run) AddILogicalLocation(logicalLocation *LogicalLocation) {
	run.LogicalLocations = append(run.LogicalLocations, logicalLocation)
}

// WithNewlineSequences sets the NewlineSequences
func (run *Run) WithNewlineSequences(newLines []string) *Run {
	run.NewlineSequences = newLines
	return run
}

// WithOriginalUriBaseIds sets the OriginalUriBaseIds
func (run *Run) WithOriginalUriBaseIds(originalUriBaseIDs map[string]*ArtifactLocation) *Run {
	run.OriginalUriBaseIDs = originalUriBaseIDs
	return run
}

// WithPolicies sets the Policies
func (run *Run) WithPolicies(policies []*ToolComponent) *Run {
	run.Policies = policies
	return run
}

// AddPolicy ...
func (run *Run) AddPolicy(policy *ToolComponent) {
	run.Policies = append(run.Policies, policy)
}

// WithRedactionTokens sets the RedactionTokens
func (run *Run) WithRedactionTokens(redactedTokens []string) *Run {
	run.RedactionTokens = redactedTokens
	return run
}

// WithRunAggregates sets the RunAggregates
func (run *Run) WithRunAggregates(runAggregates []*RunAutomationDetails) *Run {
	run.RunAggregates = runAggregates
	return run
}

// AddRunAggregate ...
func (run *Run) AddRunAggregate(runAggregate *RunAutomationDetails) {
	run.RunAggregates = append(run.RunAggregates, runAggregate)
}

// WithSpecialLocations sets the SpecialLocations
func (run *Run) WithSpecialLocations(specialLocation *SpecialLocations) *Run {
	run.SpecialLocations = specialLocation
	return run
}

// WithTaxonomies sets the Taxonomies
func (run *Run) WithTaxonomies(taxonomies []*ToolComponent) *Run {
	run.Taxonomies = taxonomies
	return run
}

// AddTaxonomy ...
func (run *Run) AddTaxonomy(taxonomy *ToolComponent) {
	run.Taxonomies = append(run.Taxonomies, taxonomy)
}

// WithThreadFlowLocations sets the ThreadFlowLocations
func (run *Run) WithThreadFlowLocations(threadFlowLocations []*ThreadFlowLocation) *Run {
	run.ThreadFlowLocations = threadFlowLocations
	return run
}

// AddThreadFlowLocation ...
func (run *Run) AddThreadFlowLocation(threadFlowLocation *ThreadFlowLocation) {
	run.ThreadFlowLocations = append(run.ThreadFlowLocations, threadFlowLocation)
}

// WithTranslations sets the Translations
func (run *Run) WithTranslations(translations []*ToolComponent) *Run {
	run.Translations = translations
	return run
}

// AddTranslation ...
func (run *Run) AddTranslation(translation *ToolComponent) {
	run.Translations = append(run.Translations, translation)
}

// WithVersionControlProvenances sets the VersionControlProvenances
func (run *Run) WithVersionControlProvenances(vcProvenance []*VersionControlDetails) *Run {
	run.VersionControlProvenance = vcProvenance
	return run
}

// AddVersionControlProvenance ...
func (run *Run) AddVersionControlProvenance(vcProvenance *VersionControlDetails) {
	run.VersionControlProvenance = append(run.VersionControlProvenance, vcProvenance)
}

// WithWebRequests sets the WebRequests
func (run *Run) WithWebRequests(webRequests []*WebRequest) *Run {
	run.WebRequests = webRequests
	return run
}

// AddWebRequest ...
func (run *Run) AddWebRequest(webRequest *WebRequest) {
	run.WebRequests = append(run.WebRequests, webRequest)
}

// WithWebResponses sets the WebResponses
func (run *Run) WithWebResponses(webResponses []*WebResponse) *Run {
	run.WebResponses = webResponses
	return run
}

// AddWebResponse ...
func (run *Run) AddWebResponse(webResponse *WebResponse) {
	run.WebResponses = append(run.WebResponses, webResponse)
}

// AddInvocation adds an invocation to the run and returns a pointer to it
func (run *Run) AddInvocation(executionSuccessful bool) *Invocation {
	i := &Invocation{
		ExecutionSuccessful: &executionSuccessful,
	}
	run.Invocations = append(run.Invocations, i)
	return i
}

// AddArtifact adds an artifact to the run and returns a pointer to it
func (run *Run) AddArtifact() *Artifact {
	a := &Artifact{
		Length: -1,
	}
	run.Artifacts = append(run.Artifacts, a)
	return a
}

// AddDistinctArtifact will handle deduplication of simple artifact additions
func (run *Run) AddDistinctArtifact(uri string) *Artifact {
	for _, artifact := range run.Artifacts {
		if *artifact.Location.URI == uri {
			return artifact
		}
	}

	a := &Artifact{
		Length: -1,
	}
	a.WithLocation(NewSimpleArtifactLocation(uri))

	run.Artifacts = append(run.Artifacts, a)
	return a
}

// AddRule returns an existing ReportingDescriptor for the ruleID or creates a new ReportingDescriptor and returns a pointer to it
func (run *Run) AddRule(ruleID string) *ReportingDescriptor {
	for _, rule := range run.Tool.Driver.Rules {
		if rule.ID == ruleID {
			return rule
		}
	}
	rule := NewRule(ruleID)
	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
	return rule
}

// CreateResultForRule returns an existing Result or creates a new one and returns a pointer to it
func (run *Run) CreateResultForRule(ruleID string) *Result {
	result := NewRuleResult(ruleID)
	run.AddResult(result)
	return result
}

// GetRuleById finds a rule by a given rule ID and returns a pointer to it
func (run *Run) GetRuleById(ruleId string) (*ReportingDescriptor, error) {
	if run.Tool.Driver != nil {
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ID == ruleId {
				return rule, nil
			}
		}
	}
	return nil, fmt.Errorf("couldn't find rule %s", ruleId)
}

// GetResultByRuleId finds the result for a ruleId and returns a pointer to it
func (run *Run) GetResultByRuleId(ruleId string) (*Result, error) {
	for _, result := range run.Results {
		if *result.RuleID == ruleId {
			return result, nil
		}
	}
	return nil, fmt.Errorf("couldn't find a result for rule %s", ruleId)
}

// DedupeArtifacts ...
func (run *Run) DedupeArtifacts() error {
	dupes := map[*Artifact]bool{}
	deduped := []*Artifact{}

	for _, a := range run.Artifacts {
		if _, ok := dupes[a]; !ok {
			dupes[a] = true
			deduped = append(deduped, a)
		}
	}
	run.Artifacts = deduped
	return nil
}
