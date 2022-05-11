package sarif

// Edge ...
type Edge struct {
	ID           string   `json:"id"`
	Label        *Message `json:"label,omitempty"`
	SourceNodeID string   `json:"sourceNodeId"`
	TargetNodeID string   `json:"targetNodeId"`
	PropertyBag

}

// NewEdge creates a new Edge and returns a pointer to it
func NewEdge(id, sourceNodeID, targetNodeID string) *Edge {
	return &Edge{
		ID:           id,
		SourceNodeID: sourceNodeID,
		TargetNodeID: targetNodeID,
	}
}

// WithID sets the ID
func (edge *Edge) WithID(id string) *Edge {
	edge.ID = id
	return edge
}

// WithLabel sets the Label
func (edge *Edge) WithLabel(label *Message) *Edge {
	edge.Label = label
	return edge
}

// WithLabelText sets the LabelText
func (edge *Edge) WithLabelText(text string) *Edge {
	edge.Label = &Message{
		Text: &text,
	}
	return edge
}

// WithLabelMarkdown sets the LabelMarkdown
func (edge *Edge) WithLabelMarkdown(markdown string) *Edge {
	edge.Label = &Message{
		Markdown: &markdown,
	}
	return edge
}
