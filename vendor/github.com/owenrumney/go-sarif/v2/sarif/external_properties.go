package sarif

// ExternalProperties ...
type ExternalProperties struct {
	Addresses              []*Address            `json:"addresses,omitempty"`
	Artifacts              []*Artifact           `json:"artifacts,omitempty"`
	Conversion             *Conversion           `json:"conversion,omitempty"`
	Driver                 *ToolComponent        `json:"driver,omitempty"`
	Extensions             []*ToolComponent      `json:"extensions,omitempty"`
	ExternalizedProperties *PropertyBag          `json:"externalizedProperties,omitempty"`
	Graphs                 []*Graph              `json:"graphs,omitempty"`
	GUID                   *string               `json:"guid,omitempty"`
	Invocations            []*Invocation         `json:"invocations,omitempty"`
	LogicalLocations       []*LogicalLocation    `json:"logicalLocations,omitempty"`
	Policies               []*ToolComponent      `json:"policies,omitempty"`
	Results                []*Result             `json:"results,omitempty"`
	RunGUID                *string               `json:"runGuid,omitempty"`
	Schema                 *string               `json:"schema,omitempty"`
	Taxonomies             []*ToolComponent      `json:"taxonomies,omitempty"`
	ThreadFlowLocations    []*ThreadFlowLocation `json:"threadFlowLocations,omitempty"`
	Translations           []*ToolComponent      `json:"translations,omitempty"`
	Version                string                `json:"version,omitempty"`
	WebRequests            []*WebRequest         `json:"webRequests,omitempty"`
	WebResponses           []*WebResponse        `json:"webResponses,omitempty"`
	PropertyBag

}

// NewExternalProperties creates a new ExternalProperties and returns a pointer to it
func NewExternalProperties() *ExternalProperties {
	return &ExternalProperties{}
}

// WithAddress sets the Address
func (externalProperties *ExternalProperties) WithAddress(addresses []*Address) *ExternalProperties {
	externalProperties.Addresses = addresses
	return externalProperties
}

// AddAddress ...
func (externalProperties *ExternalProperties) AddAddress(address *Address) {
	externalProperties.Addresses = append(externalProperties.Addresses, address)
}

// WithArtifact sets the Artifact
func (externalProperties *ExternalProperties) WithArtifact(artifacts []*Artifact) *ExternalProperties {
	externalProperties.Artifacts = artifacts
	return externalProperties
}

// AddArtifact ...
func (externalProperties *ExternalProperties) AddArtifact(artifact *Artifact) {
	externalProperties.Artifacts = append(externalProperties.Artifacts, artifact)
}

// WithConversion sets the Conversion
func (externalProperties *ExternalProperties) WithConversion(conversion *Conversion) *ExternalProperties {
	externalProperties.Conversion = conversion
	return externalProperties
}

// WithDriver sets the Driver
func (externalProperties *ExternalProperties) WithDriver(driver *ToolComponent) *ExternalProperties {
	externalProperties.Driver = driver
	return externalProperties
}

// WithExtensions sets the Extensions
func (externalProperties *ExternalProperties) WithExtensions(extensions []*ToolComponent) *ExternalProperties {
	externalProperties.Extensions = extensions
	return externalProperties
}

// AddExtension ...
func (externalProperties *ExternalProperties) AddExtension(extension *ToolComponent) {
	externalProperties.Extensions = append(externalProperties.Extensions, extension)
}

// WithExternalizedProperties sets the ExternalizedProperties
func (externalProperties *ExternalProperties) WithExternalizedProperties(externalizedProperties *PropertyBag) *ExternalProperties {
	externalProperties.ExternalizedProperties = externalizedProperties
	return externalProperties
}

// WithGraphs sets the Graphs
func (externalProperties *ExternalProperties) WithGraphs(graphs []*Graph) *ExternalProperties {
	externalProperties.Graphs = graphs
	return externalProperties
}

// AddGraph ...
func (externalProperties *ExternalProperties) AddGraph(graph *Graph) {
	externalProperties.Graphs = append(externalProperties.Graphs, graph)
}

// WithGUID sets the GUID
func (externalProperties *ExternalProperties) WithGUID(guid string) *ExternalProperties {
	externalProperties.GUID = &guid
	return externalProperties
}

// WithInvocations sets the Invocations
func (externalProperties *ExternalProperties) WithInvocations(invocations []*Invocation) *ExternalProperties {
	externalProperties.Invocations = invocations
	return externalProperties
}

// AddInvocation ...
func (externalProperties *ExternalProperties) AddInvocation(invocation *Invocation) {
	externalProperties.Invocations = append(externalProperties.Invocations, invocation)
}

// WithLogicalLocations sets the LogicalLocations
func (externalProperties *ExternalProperties) WithLogicalLocations(logicalLocations []*LogicalLocation) *ExternalProperties {
	externalProperties.LogicalLocations = logicalLocations
	return externalProperties
}

// AddLogicalLocation ...
func (externalProperties *ExternalProperties) AddLogicalLocation(logicalLocation *LogicalLocation) {
	externalProperties.LogicalLocations = append(externalProperties.LogicalLocations, logicalLocation)
}

// WithPolicies sets the Policies
func (externalProperties *ExternalProperties) WithPolicies(policies []*ToolComponent) *ExternalProperties {
	externalProperties.Policies = policies
	return externalProperties
}

// AddPolicy ...
func (externalProperties *ExternalProperties) AddPolicy(policy *ToolComponent) {
	externalProperties.Policies = append(externalProperties.Policies, policy)
}

// WithResults sets the Results
func (externalProperties *ExternalProperties) WithResults(results []*Result) *ExternalProperties {
	externalProperties.Results = results
	return externalProperties
}

// AddResult ...
func (externalProperties *ExternalProperties) AddResult(result *Result) {
	externalProperties.Results = append(externalProperties.Results, result)
}

// WithRunGUID sets the RunGUID
func (externalProperties *ExternalProperties) WithRunGUID(runGUID string) *ExternalProperties {
	externalProperties.RunGUID = &runGUID
	return externalProperties
}

// WithSchema sets the Schema
func (externalProperties *ExternalProperties) WithSchema(schema string) *ExternalProperties {
	externalProperties.Schema = &schema
	return externalProperties
}

// WithVersion sets the Version
func (externalProperties *ExternalProperties) WithVersion(version string) *ExternalProperties {
	externalProperties.Version = version
	return externalProperties
}

// WithTaxonomies sets the Taxonomies
func (externalProperties *ExternalProperties) WithTaxonomies(taxonomies []*ToolComponent) *ExternalProperties {
	externalProperties.Taxonomies = taxonomies
	return externalProperties
}

// AddTaxonomie ...
func (externalProperties *ExternalProperties) AddTaxonomie(taxonomy *ToolComponent) {
	externalProperties.Taxonomies = append(externalProperties.Taxonomies, taxonomy)
}

// WithThreadFlowLocations sets the ThreadFlowLocations
func (externalProperties *ExternalProperties) WithThreadFlowLocations(threadFlowLocations []*ThreadFlowLocation) *ExternalProperties {
	externalProperties.ThreadFlowLocations = threadFlowLocations
	return externalProperties
}

// AddThreadFlowLocations ...
func (externalProperties *ExternalProperties) AddThreadFlowLocations(threadFlowLocation *ThreadFlowLocation) {
	externalProperties.ThreadFlowLocations = append(externalProperties.ThreadFlowLocations, threadFlowLocation)
}

// WithTranslations sets the Translations
func (externalProperties *ExternalProperties) WithTranslations(translation []*ToolComponent) *ExternalProperties {
	externalProperties.Translations = translation
	return externalProperties
}

// AddTranslation ...
func (externalProperties *ExternalProperties) AddTranslation(translation *ToolComponent) {
	externalProperties.Translations = append(externalProperties.Translations, translation)
}

// WithWebRequests sets the WebRequests
func (externalProperties *ExternalProperties) WithWebRequests(webRequests []*WebRequest) *ExternalProperties {
	externalProperties.WebRequests = webRequests
	return externalProperties
}

// AddWebRequest ...
func (externalProperties *ExternalProperties) AddWebRequest(webRequest *WebRequest) {
	externalProperties.WebRequests = append(externalProperties.WebRequests, webRequest)
}

// WithWebResponses sets the WebResponses
func (externalProperties *ExternalProperties) WithWebResponses(webResponses []*WebResponse) *ExternalProperties {
	externalProperties.WebResponses = webResponses
	return externalProperties
}

// AddWebResponse ...
func (externalProperties *ExternalProperties) AddWebResponse(webResponse *WebResponse) {
	externalProperties.WebResponses = append(externalProperties.WebResponses, webResponse)
}
