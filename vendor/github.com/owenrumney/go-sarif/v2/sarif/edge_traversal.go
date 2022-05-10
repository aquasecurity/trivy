package sarif

// EdgeTraversal ...
type EdgeTraversal struct {
	EdgeID            string                               `json:"edgeId"`
	FinalState        map[string]*MultiformatMessageString `json:"finalState,omitempty"`
	Message           *Message                             `json:"message,omitempty"`
	StepOverEdgeCount *int                                 `json:"stepOverEdgeCount,omitempty"`
	PropertyBag

}

// NewEdgeTraversal creates a new EdgeTraversal and returns a pointer to it
func NewEdgeTraversal(edgeID string) *EdgeTraversal {
	return &EdgeTraversal{
		EdgeID: edgeID,
	}
}

// WithDescription sets the Description
func (edgeTraversal *EdgeTraversal) WithDescription(message *Message) *EdgeTraversal {
	edgeTraversal.Message = message
	return edgeTraversal
}

// WithDescriptionText sets the DescriptionText
func (edgeTraversal *EdgeTraversal) WithDescriptionText(text string) *EdgeTraversal {
	edgeTraversal.Message = &Message{
		Text: &text,
	}
	return edgeTraversal
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (edgeTraversal *EdgeTraversal) WithDescriptionMarkdown(markdown string) *EdgeTraversal {
	edgeTraversal.Message = &Message{
		Markdown: &markdown,
	}
	return edgeTraversal
}

// WithFinalState sets the FinalState
func (edgeTraversal *EdgeTraversal) WithFinalState(finalState map[string]*MultiformatMessageString) *EdgeTraversal {
	edgeTraversal.FinalState = finalState
	return edgeTraversal
}

// SetFinalState ...
func (edgeTraversal *EdgeTraversal) SetFinalState(key string, state *MultiformatMessageString) {
	edgeTraversal.FinalState[key] = state
}

// WithStepOverEdgeCount sets the StepOverEdgeCount
func (edgeTraversal *EdgeTraversal) WithStepOverEdgeCount(stepOverEdgeCount int) *EdgeTraversal {
	edgeTraversal.StepOverEdgeCount = &stepOverEdgeCount
	return edgeTraversal
}
