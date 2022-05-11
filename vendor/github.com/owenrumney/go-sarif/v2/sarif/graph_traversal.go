package sarif

// GraphTraversal ...
type GraphTraversal struct {
	Description      *Message                             `json:"description,omitempty"`
	EdgeTraversals   []*EdgeTraversal                     `json:"edgeTraversals,omitempty"`
	ImmutableState   map[string]*MultiformatMessageString `json:"immutableState,omitempty"`
	InitialState     map[string]*MultiformatMessageString `json:"initialState,omitempty"`
	ResultGraphIndex *int                                 `json:"resultGraphIndex,omitempty"`
	RunGraphIndex    *int                                 `json:"runGraphIndex,omitempty"`
	PropertyBag

}

// NewGraphTraversal creates a new GraphTraversal and returns a pointer to it
func NewGraphTraversal() *GraphTraversal {
	return &GraphTraversal{}
}

// WithDescription sets the Description
func (graphTraversal *GraphTraversal) WithDescription(message *Message) *GraphTraversal {
	graphTraversal.Description = message
	return graphTraversal
}

// WithDescriptionText sets the DescriptionText
func (graphTraversal *GraphTraversal) WithDescriptionText(text string) *GraphTraversal {
	if graphTraversal.Description == nil {
		graphTraversal.Description = &Message{}
	}
	graphTraversal.Description.Text = &text
	return graphTraversal
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (graphTraversal *GraphTraversal) WithDescriptionMarkdown(markdown string) *GraphTraversal {
	if graphTraversal.Description == nil {
		graphTraversal.Description = &Message{}
	}
	graphTraversal.Description.Markdown = &markdown
	return graphTraversal
}

// WithEdgeTraversals sets the EdgeTraversals
func (graphTraversal *GraphTraversal) WithEdgeTraversals(edgeTraversals []*EdgeTraversal) *GraphTraversal {
	graphTraversal.EdgeTraversals = edgeTraversals
	return graphTraversal
}

// AddEdge ...
func (graphTraversal *GraphTraversal) AddEdge(edgeTraversal *EdgeTraversal) {
	graphTraversal.EdgeTraversals = append(graphTraversal.EdgeTraversals, edgeTraversal)
}

// WithResultGraphIndex sets the ResultGraphIndex
func (graphTraversal *GraphTraversal) WithResultGraphIndex(index int) *GraphTraversal {
	graphTraversal.ResultGraphIndex = &index
	return graphTraversal
}

// WithRunGraphIndex sets the RunGraphIndex
func (graphTraversal *GraphTraversal) WithRunGraphIndex(index int) *GraphTraversal {
	graphTraversal.RunGraphIndex = &index
	return graphTraversal
}

// WithImmutableState sets the ImmutableState
func (graphTraversal *GraphTraversal) WithImmutableState(immutableState map[string]*MultiformatMessageString) *GraphTraversal {
	graphTraversal.ImmutableState = immutableState
	return graphTraversal
}

// WithInitialState sets the InitialState
func (graphTraversal *GraphTraversal) WithInitialState(initialState map[string]*MultiformatMessageString) *GraphTraversal {
	graphTraversal.InitialState = initialState
	return graphTraversal
}
