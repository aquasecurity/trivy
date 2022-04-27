package sarif

// CodeFlow ...
type CodeFlow struct {
	Message     *Message      `json:"message,omitempty"`
	ThreadFlows []*ThreadFlow `json:"threadFlows,omitempty"`
	PropertyBag

}

// NewCodeFlow creates a new CodeFlow and returns a pointer to it
func NewCodeFlow() *CodeFlow {
	return &CodeFlow{}
}

// WithMessage sets the Message
func (codeFlow *CodeFlow) WithMessage(message *Message) *CodeFlow {
	codeFlow.Message = message
	return codeFlow
}

// WithTextMessage sets the Message text
func (codeFlow *CodeFlow) WithTextMessage(text string) *CodeFlow {
	if codeFlow.Message == nil {
		codeFlow.Message = &Message{}
	}
	codeFlow.Message.Text = &text
	return codeFlow
}

// WithMessageMarkdown sets the Message markdown
func (codeFlow *CodeFlow) WithMessageMarkdown(markdown string) *CodeFlow {
	if codeFlow.Message == nil {
		codeFlow.Message = &Message{}
	}
	codeFlow.Message.Markdown = &markdown
	return codeFlow
}

// WithThreadFlows sets the ThreadFlows
func (codeFlow *CodeFlow) WithThreadFlows(threadFlows []*ThreadFlow) *CodeFlow {
	codeFlow.ThreadFlows = threadFlows

	return codeFlow
}

// AddThreadFlow ...
func (codeFlow *CodeFlow) AddThreadFlow(threadFlow *ThreadFlow) {
	codeFlow.ThreadFlows = append(codeFlow.ThreadFlows, threadFlow)
}
