package sarif

import "time"

// ThreadFlowLocation ...
type ThreadFlowLocation struct {
	ExecutionOrder   *int                                 `json:"executionOrder,omitempty"`
	ExecutionTimeUTC *time.Time                           `json:"executionTimeUtc,omitempty"`
	Importance       interface{}                          `json:"importance,omitempty"`
	Index            *int                                 `json:"index,omitempty"`
	Kinds            []string                             `json:"kinds,omitempty"`
	Location         *Location                            `json:"location,omitempty"`
	Module           *string                              `json:"module,omitempty"`
	NestingLevel     *int                                 `json:"nestingLevel,omitempty"`
	Stack            *Stack                               `json:"stack,omitempty"`
	State            map[string]*MultiformatMessageString `json:"state,omitempty"`
	Taxa             []*ReportingDescriptorReference      `json:"taxa,omitempty"`
	WebRequest       *WebRequest                          `json:"webRequest,omitempty"`
	WebResponse      *WebResponse                         `json:"webResponse,omitempty"`
	PropertyBag

}

// NewThreadFlowLocation creates a new ThreadFlowLocation and returns a pointer to it
func NewThreadFlowLocation() *ThreadFlowLocation {
	return &ThreadFlowLocation{}
}

// WithExecutionOrder sets the ExecutionOrder
func (threadFlowLocation *ThreadFlowLocation) WithExecutionOrder(order int) *ThreadFlowLocation {
	threadFlowLocation.ExecutionOrder = &order
	return threadFlowLocation
}

// WithExecutionTimeUTC sets the ExecutionTimeUTC
func (threadFlowLocation *ThreadFlowLocation) WithExecutionTimeUTC(executionTimeUTC *time.Time) *ThreadFlowLocation {
	threadFlowLocation.ExecutionTimeUTC = executionTimeUTC
	return threadFlowLocation
}

// WithImportance sets the Importance
func (threadFlowLocation *ThreadFlowLocation) WithImportance(importance interface{}) *ThreadFlowLocation {
	threadFlowLocation.Importance = importance
	return threadFlowLocation
}

// WithIndex sets the Index
func (threadFlowLocation *ThreadFlowLocation) WithIndex(index int) *ThreadFlowLocation {
	threadFlowLocation.Index = &index
	return threadFlowLocation
}

// WithKinds sets the Kinds
func (threadFlowLocation *ThreadFlowLocation) WithKinds(kinds []string) *ThreadFlowLocation {
	threadFlowLocation.Kinds = kinds
	return threadFlowLocation
}

// AddKind ...
func (threadFlowLocation *ThreadFlowLocation) AddKind(kind string) {
	threadFlowLocation.Kinds = append(threadFlowLocation.Kinds, kind)
}

// WithLocation sets the Location
func (threadFlowLocation *ThreadFlowLocation) WithLocation(location *Location) *ThreadFlowLocation {
	threadFlowLocation.Location = location
	return threadFlowLocation
}

// WithModule sets the Module
func (threadFlowLocation *ThreadFlowLocation) WithModule(module string) *ThreadFlowLocation {
	threadFlowLocation.Module = &module
	return threadFlowLocation
}

// WithNestingLevel sets the NestingLevel
func (threadFlowLocation *ThreadFlowLocation) WithNestingLevel(nestingLevel int) *ThreadFlowLocation {
	threadFlowLocation.NestingLevel = &nestingLevel
	return threadFlowLocation
}

// WithStack sets the Stack
func (threadFlowLocation *ThreadFlowLocation) WithStack(stack *Stack) *ThreadFlowLocation {
	threadFlowLocation.Stack = stack
	return threadFlowLocation
}

// WithState sets the State
func (threadFlowLocation *ThreadFlowLocation) WithState(state map[string]*MultiformatMessageString) *ThreadFlowLocation {
	threadFlowLocation.State = state
	return threadFlowLocation
}

// WithTaxa sets the Taxa
func (threadFlowLocation *ThreadFlowLocation) WithTaxa(taxa []*ReportingDescriptorReference) *ThreadFlowLocation {
	threadFlowLocation.Taxa = taxa
	return threadFlowLocation
}

// AddTaxa ...
func (threadFlowLocation *ThreadFlowLocation) AddTaxa(taxa *ReportingDescriptorReference) {
	threadFlowLocation.Taxa = append(threadFlowLocation.Taxa, taxa)
}

// WithWebRequest sets the WebRequest
func (threadFlowLocation *ThreadFlowLocation) WithWebRequest(webRequest *WebRequest) *ThreadFlowLocation {
	threadFlowLocation.WebRequest = webRequest
	return threadFlowLocation
}

// WithWebResponse sets the WebResponse
func (threadFlowLocation *ThreadFlowLocation) WithWebResponse(webResponse *WebResponse) *ThreadFlowLocation {
	threadFlowLocation.WebResponse = webResponse
	return threadFlowLocation
}
