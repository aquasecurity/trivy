package sarif

// Graph ...
type Graph struct {
	Description *Message `json:"description,omitempty"`
	Edges       []*Edge  `json:"edges,omitempty"`
	Nodes       []*Node  `json:"nodes,omitempty"`
	PropertyBag

}

// NewGraph creates a new Graph and returns a pointer to it
func NewGraph() *Graph {
	return &Graph{}
}

// WithDescription sets the Description
func (graph *Graph) WithDescription(message *Message) *Graph {
	graph.Description = message
	return graph
}

// WithDescriptionText sets the DescriptionText
func (graph *Graph) WithDescriptionText(text string) *Graph {
	if graph.Description == nil {
		graph.Description = &Message{}
	}
	graph.Description.Text = &text
	return graph
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (graph *Graph) WithDescriptionMarkdown(markdown string) *Graph {
	if graph.Description == nil {
		graph.Description = &Message{}
	}
	graph.Description.Markdown = &markdown
	return graph
}

// WithEdges sets the Edges
func (graph *Graph) WithEdges(edges []*Edge) *Graph {
	graph.Edges = edges
	return graph
}

// AddEdge ...
func (graph *Graph) AddEdge(edge *Edge) {
	graph.Edges = append(graph.Edges, edge)
}

// WithNodes sets the Nodes
func (graph *Graph) WithNodes(nodes []*Node) *Graph {
	graph.Nodes = nodes
	return graph
}

// AddNode ...
func (graph *Graph) AddNode(node *Node) {
	graph.Nodes = append(graph.Nodes, node)
}
