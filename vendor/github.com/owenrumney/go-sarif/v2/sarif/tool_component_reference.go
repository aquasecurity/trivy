package sarif

// ToolComponentReference ...
type ToolComponentReference struct {
	Name  *string `json:"name"`
	Index *uint   `json:"index"`
	Guid  *string `json:"guid"`
	PropertyBag

}

// NewToolComponentReference creates a new ToolComponentReference and returns a pointer to it
func NewToolComponentReference() *ToolComponentReference {
	return &ToolComponentReference{}
}

// WithName sets the Name
func (t *ToolComponentReference) WithName(name string) *ToolComponentReference {
	t.Name = &name
	return t
}

// WithIndex sets the Index
func (t *ToolComponentReference) WithIndex(index int) *ToolComponentReference {
	i := uint(index)
	t.Index = &i
	return t
}

// WithGuid sets the Guid
func (t *ToolComponentReference) WithGuid(guid string) *ToolComponentReference {
	t.Guid = &guid
	return t
}
