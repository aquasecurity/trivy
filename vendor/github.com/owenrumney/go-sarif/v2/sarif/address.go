package sarif

// Address ...
type Address struct {
	Index              *uint   `json:"index,omitempty"`
	AbsoluteAddress    *uint   `json:"absoluteAddress,omitempty"`
	RelativeAddress    *int    `json:"relativeAddress,omitempty"`
	OffsetFromParent   *int    `json:"offsetFromParent,omitempty"`
	Length             *int    `json:"length,omitempty"`
	Name               *string `json:"name,omitempty"`
	FullyQualifiedName *string `json:"fullyQualifiedName,omitempty"`
	Kind               *string `json:"kind,omitempty"`
	ParentIndex        *uint   `json:"parentIndex,omitempty"`
	PropertyBag
}

// NewAddress create a new Address and returns a pointer to it
func NewAddress() *Address {
	return &Address{}
}

// WithIndex sets the Index
func (address *Address) WithIndex(index int) *Address {
	i := uint(index)
	address.Index = &i
	return address
}

// WithAbsoluteAddress sets the AbsoluteAddress
func (address *Address) WithAbsoluteAddress(absoluteAddress int) *Address {
	i := uint(absoluteAddress)
	address.AbsoluteAddress = &i
	return address
}

// WithRelativeAddress sets the RelativeAddress
func (address *Address) WithRelativeAddress(relativeAddress int) *Address {
	address.RelativeAddress = &relativeAddress
	return address
}

// WithOffsetFromParent sets the OffsetFromParent
func (address *Address) WithOffsetFromParent(offsetFromParent int) *Address {
	address.OffsetFromParent = &offsetFromParent
	return address
}

// WithLength sets the Length
func (address *Address) WithLength(length int) *Address {
	address.Length = &length
	return address
}

// WithName sets the Name
func (address *Address) WithName(name string) *Address {
	address.Name = &name
	return address
}

// WithFullyQualifiedName sets the FullyQualifiedName
func (address *Address) WithFullyQualifiedName(fullyQualifiedName string) *Address {
	address.FullyQualifiedName = &fullyQualifiedName
	return address
}

// WithKind sets the Kind
func (address *Address) WithKind(kind string) *Address {
	address.Kind = &kind
	return address
}

// WithParentIndex sets the ParentIndex
func (address *Address) WithParentIndex(parentIndex int) *Address {
	i := uint(parentIndex)
	address.ParentIndex = &i
	return address
}
