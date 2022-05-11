package sarif

// LogicalLocation ...
type LogicalLocation struct {
	Index              *uint   `json:"index,omitempty"`
	Name               *string `json:"name,omitempty"`
	FullyQualifiedName *string `json:"fullyQualifiedName,omitempty"`
	DecoratedName      *string `json:"decoratedName,omitempty"`
	Kind               *string `json:"kind,omitempty"`
	ParentIndex        *uint   `json:"parentIndex,omitempty"`
	PropertyBag
}

// NewLogicalLocation creates a new LogicalLocation and returns a pointer to it
func NewLogicalLocation() *LogicalLocation {
	return &LogicalLocation{}
}

// WithIndex sets the Index
func (l *LogicalLocation) WithIndex(index int) *LogicalLocation {
	i := uint(index)
	l.Index = &i
	return l
}

// WithName sets the Name
func (l *LogicalLocation) WithName(name string) *LogicalLocation {
	l.Name = &name
	return l
}

// WithFullyQualifiedName sets the FullyQualifiedName
func (l *LogicalLocation) WithFullyQualifiedName(fullyQualifiedName string) *LogicalLocation {
	l.FullyQualifiedName = &fullyQualifiedName
	return l
}

// WithDecoratedName sets the DecoratedName
func (l *LogicalLocation) WithDecoratedName(decoratedName string) *LogicalLocation {
	l.DecoratedName = &decoratedName
	return l
}

// WithKind sets the Kind
func (l *LogicalLocation) WithKind(kind string) *LogicalLocation {
	l.Kind = &kind
	return l
}

// WithParentIndex sets the ParentIndex
func (l *LogicalLocation) WithParentIndex(parentIndex int) *LogicalLocation {
	i := uint(parentIndex)
	l.ParentIndex = &i
	return l
}
