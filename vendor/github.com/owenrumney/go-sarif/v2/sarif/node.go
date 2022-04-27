package sarif

// Node ...
type Node struct {
	Children []*Node   `json:"children,omitempty"`
	ID       string    `json:"id"`
	Label    *Message  `json:"label,omitempty"`
	Location *Location `json:"location,omitempty"`
	PropertyBag
}

// NewNode creates a new Node and returns a pointer to it
func NewNode(id string) *Node {
	return &Node{
		ID: id,
	}
}

// WithChildren sets the Children
func (node *Node) WithChildren(children []*Node) *Node {
	node.Children = children
	return node
}

// AddChild ...
func (node *Node) AddChild(child *Node) {
	node.Children = append(node.Children, child)
}

// WithLabel sets the Label
func (node *Node) WithLabel(message *Message) *Node {
	node.Label = message
	return node
}

// WithLabelText sets the LabelText
func (node *Node) WithLabelText(text string) *Node {
	if node.Label == nil {
		node.Label = &Message{}
	}
	node.Label.Text = &text
	return node
}

// WithLabelMarkdown sets the LabelMarkdown
func (node *Node) WithLabelMarkdown(markdown string) *Node {
	if node.Label == nil {
		node.Label = &Message{}
	}
	node.Label.Markdown = &markdown
	return node
}
