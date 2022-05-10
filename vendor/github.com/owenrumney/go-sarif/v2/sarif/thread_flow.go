package sarif

// ThreadFlow ...
type ThreadFlow struct {
	ID             *string                              `json:"id,omitempty"`
	ImmutableState map[string]*MultiformatMessageString `json:"immutableState,omitempty"`
	InitialState   map[string]*MultiformatMessageString `json:"initialState,omitempty"`
	Locations      []*ThreadFlowLocation                `json:"locations"`
	Message        *Message                             `json:"message,omitempty"`
	PropertyBag

}

// NewThreadFlow creates a new ThreadFlow and returns a pointer to it
func NewThreadFlow() *ThreadFlow {
	return &ThreadFlow{}
}

// WithID sets the ID
func (threadFlow *ThreadFlow) WithID(id string) *ThreadFlow {
	threadFlow.ID = &id
	return threadFlow
}

// WithImmutableState sets the ImmutableState
func (threadFlow *ThreadFlow) WithImmutableState(immutableState map[string]*MultiformatMessageString) *ThreadFlow {
	threadFlow.ImmutableState = immutableState
	return threadFlow
}

// WithInitialState sets the InitialState
func (threadFlow *ThreadFlow) WithInitialState(initialState map[string]*MultiformatMessageString) *ThreadFlow {
	threadFlow.InitialState = initialState
	return threadFlow
}

// WithLocations sets the Locations
func (threadFlow *ThreadFlow) WithLocations(locations []*ThreadFlowLocation) *ThreadFlow {
	threadFlow.Locations = locations
	return threadFlow
}

// AddLocation ...
func (threadFlow *ThreadFlow) AddLocation(location *ThreadFlowLocation) {
	threadFlow.Locations = append(threadFlow.Locations, location)
}

// WithMessage sets the Message
func (threadFlow *ThreadFlow) WithMessage(message *Message) *ThreadFlow {
	threadFlow.Message = message
	return threadFlow
}

// WithTextMessage sets the Message text
func (threadFlow *ThreadFlow) WithTextMessage(text string) *ThreadFlow {
	if threadFlow.Message == nil {
		threadFlow.Message = &Message{}
	}
	threadFlow.Message.Text = &text
	return threadFlow
}

// WithMessageMarkdown sets the Message markdown
func (threadFlow *ThreadFlow) WithMessageMarkdown(markdown string) *ThreadFlow {
	if threadFlow.Message == nil {
		threadFlow.Message = &Message{}
	}
	threadFlow.Message.Markdown = &markdown
	return threadFlow
}
