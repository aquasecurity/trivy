package sarif

// ExternalPropertyFileReferences ...
type ExternalPropertyFileReferences struct {
	Addresses              []*ExternalPropertyFileReference `json:"addresses,omitempty"`
	Artifacts              []*ExternalPropertyFileReference `json:"artifacts,omitempty"`
	Conversion             *ExternalPropertyFileReference   `json:"conversion,omitempty"`
	Driver                 *ExternalPropertyFileReference   `json:"driver,omitempty"`
	Extensions             []*ExternalPropertyFileReference `json:"extensions,omitempty"`
	ExternalizedProperties *ExternalPropertyFileReference   `json:"externalizedProperties,omitempty"`
	Graphs                 []*ExternalPropertyFileReference `json:"graphs,omitempty"`
	Invocations            []*ExternalPropertyFileReference `json:"invocations,omitempty"`
	LogicalLocations       []*ExternalPropertyFileReference `json:"logicalLocations,omitempty"`
	Policies               []*ExternalPropertyFileReference `json:"policies,omitempty"`
	Properties             *PropertyBag                     `json:"properties,omitempty"`
	Results                []*ExternalPropertyFileReference `json:"results,omitempty"`
	Taxonomies             []*ExternalPropertyFileReference `json:"taxonomies,omitempty"`
	ThreadFlowLocations    []*ExternalPropertyFileReference `json:"threadFlowLocations,omitempty"`
	Translations           []*ExternalPropertyFileReference `json:"translations,omitempty"`
	WebRequests            []*ExternalPropertyFileReference `json:"webRequests,omitempty"`
	WebResponses           []*ExternalPropertyFileReference `json:"webResponses,omitempty"`
	PropertyBag

}

// NewExternalPropertyFileReferences creates a new ExternalPropertyFileReferences and returns a pointer to it
func NewExternalPropertyFileReferences() *ExternalPropertyFileReferences {
	return &ExternalPropertyFileReferences{}
}

// WithAddress sets the Address
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithAddress(addresses []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Addresses = addresses
	return externalPropertyFileReferences
}

// AddAddress ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddAddress(address *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Addresses = append(externalPropertyFileReferences.Addresses, address)
}

// WithArtifact sets the Artifact
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithArtifact(artifacts []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Artifacts = artifacts
	return externalPropertyFileReferences
}

// AddArtifact ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddArtifact(artifact *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Artifacts = append(externalPropertyFileReferences.Artifacts, artifact)
}

// WithConversion sets the Conversion
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithConversion(conversion *ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Conversion = conversion
	return externalPropertyFileReferences
}

// WithDriver sets the Driver
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithDriver(driver *ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Driver = driver
	return externalPropertyFileReferences
}

// WithExtensions sets the Extensions
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithExtensions(extensions []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Extensions = extensions
	return externalPropertyFileReferences
}

// AddExtension ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddExtension(extension *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Extensions = append(externalPropertyFileReferences.Extensions, extension)
}

// WithExternalizedProperties sets the ExternalizedProperties
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithExternalizedProperties(externalizedProperties *ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.ExternalizedProperties = externalizedProperties
	return externalPropertyFileReferences
}

// WithGraphs sets the Graphs
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithGraphs(graphs []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Graphs = graphs
	return externalPropertyFileReferences
}

// AddGraph ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddGraph(graph *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Graphs = append(externalPropertyFileReferences.Graphs, graph)
}

// WithInvocations sets the Invocations
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithInvocations(invocations []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Invocations = invocations
	return externalPropertyFileReferences
}

// AddInvocation ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddInvocation(invocation *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Invocations = append(externalPropertyFileReferences.Invocations, invocation)
}

// WithLogicalLocations sets the LogicalLocations
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithLogicalLocations(logicalLocations []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.LogicalLocations = logicalLocations
	return externalPropertyFileReferences
}

// AddLogicalLocation ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddLogicalLocation(logicalLocation *ExternalPropertyFileReference) {
	externalPropertyFileReferences.LogicalLocations = append(externalPropertyFileReferences.LogicalLocations, logicalLocation)
}

// WithPolicies sets the Policies
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithPolicies(policies []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Policies = policies
	return externalPropertyFileReferences
}

// AddPolicy ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddPolicy(policy *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Policies = append(externalPropertyFileReferences.Policies, policy)
}

// WithResults sets the Results
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithResults(results []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Results = results
	return externalPropertyFileReferences
}

// AddResult ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddResult(result *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Results = append(externalPropertyFileReferences.Results, result)
}

// WithTaxonomies sets the Taxonomies
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithTaxonomies(taxonomies []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Taxonomies = taxonomies
	return externalPropertyFileReferences
}

// AddTaxonomie ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddTaxonomie(taxonomy *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Taxonomies = append(externalPropertyFileReferences.Taxonomies, taxonomy)
}

// WithThreadFlowLocations sets the ThreadFlowLocations
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithThreadFlowLocations(threadFlowLocations []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.ThreadFlowLocations = threadFlowLocations
	return externalPropertyFileReferences
}

// AddThreadFlowLocations ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddThreadFlowLocations(threadFlowLocation *ExternalPropertyFileReference) {
	externalPropertyFileReferences.ThreadFlowLocations = append(externalPropertyFileReferences.ThreadFlowLocations, threadFlowLocation)
}

// WithTranslations sets the Translations
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithTranslations(translation []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.Translations = translation
	return externalPropertyFileReferences
}

// AddTranslation ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddTranslation(translation *ExternalPropertyFileReference) {
	externalPropertyFileReferences.Translations = append(externalPropertyFileReferences.Translations, translation)
}

// WithWebRequests sets the WebRequests
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithWebRequests(webRequests []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.WebRequests = webRequests
	return externalPropertyFileReferences
}

// AddWebRequest ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddWebRequest(webRequest *ExternalPropertyFileReference) {
	externalPropertyFileReferences.WebRequests = append(externalPropertyFileReferences.WebRequests, webRequest)
}

// WithWebResponses sets the WebResponses
func (externalPropertyFileReferences *ExternalPropertyFileReferences) WithWebResponses(webResponses []*ExternalPropertyFileReference) *ExternalPropertyFileReferences {
	externalPropertyFileReferences.WebResponses = webResponses
	return externalPropertyFileReferences
}

// AddWebResponse ...
func (externalPropertyFileReferences *ExternalPropertyFileReferences) AddWebResponse(webResponse *ExternalPropertyFileReference) {
	externalPropertyFileReferences.WebResponses = append(externalPropertyFileReferences.WebResponses, webResponse)
}
