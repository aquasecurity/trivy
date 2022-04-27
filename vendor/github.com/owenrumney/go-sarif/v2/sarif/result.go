package sarif

// Result represents the results block in the sarif report
type Result struct {
	PropertyBag
	Guid                *string                         `json:"guid,omitempty"`
	CorrelationGuid     *string                         `json:"correlationGuid,omitempty"`
	RuleID              *string                         `json:"ruleId,omitempty"`
	RuleIndex           *uint                           `json:"ruleIndex,omitempty"`
	Rule                *ReportingDescriptorReference   `json:"rule,omitempty"`
	Taxa                []*ReportingDescriptorReference `json:"taxa,omitempty"`
	Kind                *string                         `json:"kind,omitempty"`
	Level               *string                         `json:"level,omitempty"`
	Message             Message                         `json:"message"`
	Locations           []*Location                     `json:"locations,omitempty"`
	AnalysisTarget      *ArtifactLocation               `json:"analysisTarget,omitempty"`
	WebRequest          *WebRequest                     `json:"webRequest,omitempty"`
	WebResponse         *WebResponse                    `json:"webResponse,omitempty"`
	Fingerprints        map[string]interface{}          `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]interface{}          `json:"partialFingerprints,omitempty"`
	CodeFlows           []*CodeFlow                     `json:"codeFlows,omitempty"`
	Graphs              []*Graph                        `json:"graphs,omitempty"`
	GraphTraversals     []*GraphTraversal               `json:"graphTraversals,omitempty"`
	Stacks              []*Stack                        `json:"stacks,omitempty"`
	RelatedLocations    []*Location                     `json:"relatedLocations,omitempty"`
	Suppressions        []*Suppression                  `json:"suppressions,omitempty"`
	BaselineState       *string                         `json:"baselineState,omitempty"`
	Rank                *float32                        `json:"rank,omitempty"`
	Attachments         []*Attachment                   `json:"attachments,omitempty"`
	WorkItemUris        []string                        `json:"workItemUris,omitempty"` // can be null
	HostedViewerUri     *string                         `json:"hostedViewerUri,omitempty"`
	Provenance          *ResultProvenance               `json:"provenance,omitempty"`
	Fixes               []*Fix                          `json:"fixes,omitempty"`
	OccurrenceCount     *uint                           `json:"occurrenceCount,omitempty"`
}

// NewRuleResult ...
func NewRuleResult(ruleID string) *Result {
	return &Result{
		RuleID: &ruleID,
	}
}

// WithGuid sets the Guid
func (result *Result) WithGuid(guid string) *Result {
	result.Guid = &guid
	return result
}

// WithCorrelationGuid sets the CorrelationGuid
func (result *Result) WithCorrelationGuid(correlationGuid string) *Result {
	result.CorrelationGuid = &correlationGuid
	return result
}

// WithRuleIndex sets the RuleIndex
func (result *Result) WithRuleIndex(ruleIndex int) *Result {
	index := uint(ruleIndex)
	result.RuleIndex = &index
	return result
}

// WithRule sets the Rule
func (result *Result) WithRule(rule *ReportingDescriptorReference) *Result {
	result.Rule = rule
	return result
}

// WithTaxa sets the Taxa
func (result *Result) WithTaxa(taxa []*ReportingDescriptorReference) *Result {
	result.Taxa = taxa
	return result
}

// AddTaxa ...
func (result *Result) AddTaxa(taxa *ReportingDescriptorReference) {
	result.Taxa = append(result.Taxa, taxa)
}

// WithKind sets the Kind
func (result *Result) WithKind(kind string) *Result {
	result.Kind = &kind
	return result
}

// WithLevel sets the Level
func (result *Result) WithLevel(level string) *Result {
	result.Level = &level
	return result
}

// WithMessage sets the Message
func (result *Result) WithMessage(message *Message) *Result {
	result.Message = *message
	return result
}

// WithLocations sets the Locations
func (result *Result) WithLocations(locations []*Location) *Result {
	result.Locations = locations
	return result
}

// AddLocation ...
func (result *Result) AddLocation(location *Location) {
	result.Locations = append(result.Locations, location)
}

// WithAnalysisTarget sets the AnalysisTarget
func (result *Result) WithAnalysisTarget(target *ArtifactLocation) *Result {
	result.AnalysisTarget = target
	return result
}

// WithFingerPrints sets the FingerPrints
func (result *Result) WithFingerPrints(fingerPrints map[string]interface{}) *Result {
	result.Fingerprints = fingerPrints
	return result
}

// SetFingerPrint ...
func (result *Result) SetFingerPrint(name string, value interface{}) {
	result.Fingerprints[name] = value
}

// WithPartialFingerPrints sets the PartialFingerPrints
func (result *Result) WithPartialFingerPrints(fingerPrints map[string]interface{}) *Result {
	result.PartialFingerprints = fingerPrints
	return result
}

// SetPartialFingerPrint ...
func (result *Result) SetPartialFingerPrint(name string, value interface{}) {
	result.PartialFingerprints[name] = value
}

// WithCodeFlows sets the CodeFlows
func (result *Result) WithCodeFlows(codeFlows []*CodeFlow) *Result {
	result.CodeFlows = codeFlows
	return result
}

// AddCodeFlow ...
func (result *Result) AddCodeFlow(codeFlow *CodeFlow) {
	result.CodeFlows = append(result.CodeFlows, codeFlow)

}

// WithGraphs sets the Graphs
func (result *Result) WithGraphs(graphs []*Graph) *Result {
	result.Graphs = graphs
	return result
}

// AddGraph ...
func (result *Result) AddGraph(graph *Graph) {
	result.Graphs = append(result.Graphs, graph)

}

// WithGraphTraversal sets the GraphTraversal
func (result *Result) WithGraphTraversal(graphTraversals []*GraphTraversal) *Result {
	result.GraphTraversals = graphTraversals
	return result
}

// AddGraphTraversal ...
func (result *Result) AddGraphTraversal(graphTraversal *GraphTraversal) {
	result.GraphTraversals = append(result.GraphTraversals, graphTraversal)

}

// WithStack sets the Stack
func (result *Result) WithStack(stacks []*Stack) *Result {
	result.Stacks = stacks
	return result
}

// AddStack ...
func (result *Result) AddStack(stack *Stack) {
	result.Stacks = append(result.Stacks, stack)

}

// WithRelatedLocations sets the RelatedLocations
func (result *Result) WithRelatedLocations(locations []*Location) *Result {
	result.RelatedLocations = locations
	return result
}

// AddRelatedLocation ...
func (result *Result) AddRelatedLocation(location *Location) *Result {
	result.RelatedLocations = append(result.RelatedLocations, location)
	return result
}

// WithSuppression sets the Suppression
func (result *Result) WithSuppression(suppressions []*Suppression) *Result {
	result.Suppressions = suppressions
	return result
}

// AddSuppression ...
func (result *Result) AddSuppression(suppression *Suppression) {
	result.Suppressions = append(result.Suppressions, suppression)

}

// WithBaselineState sets the BaselineState
func (result *Result) WithBaselineState(state string) *Result {
	result.BaselineState = &state
	return result
}

// WithRank sets the Rank
func (result *Result) WithRank(rank float32) *Result {
	result.Rank = &rank
	return result
}

// WithAttachments sets the Attachments
func (result *Result) WithAttachments(attachments []*Attachment) *Result {
	result.Attachments = attachments
	return result
}

// AddAttachment ...
func (result *Result) AddAttachment(attachments *Attachment) {
	result.Attachments = append(result.Attachments, attachments)

}

// WithWorkItemUris sets the WorkItemUris
func (result *Result) WithWorkItemUris(workItemUris []string) *Result {
	result.WorkItemUris = workItemUris
	return result
}

// AddWorkItemUri ...
func (result *Result) AddWorkItemUri(workItemUri string) {
	result.WorkItemUris = append(result.WorkItemUris, workItemUri)

}

// WithHostedViewerUri sets the HostedViewerUri
func (result *Result) WithHostedViewerUri(hostedViewerUri string) *Result {
	result.HostedViewerUri = &hostedViewerUri
	return result
}

// WithFix sets the Fix
func (result *Result) WithFix(fixes []*Fix) *Result {
	result.Fixes = fixes
	return result
}

// AddFix ...
func (result *Result) AddFix(fix *Fix) {
	result.Fixes = append(result.Fixes, fix)
}

// WithOccurrenceCount sets the OccurrenceCount
func (result *Result) WithOccurrenceCount(occurrenceCount int) *Result {
	count := uint(occurrenceCount)
	result.OccurrenceCount = &count
	return result
}
