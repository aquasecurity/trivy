package types

type metadataProvider interface {
	GetMetadata() Metadata
	GetRawValue() interface{}
}

type Metadata struct {
	rnge           Range
	ref            Reference
	isManaged      bool
	isDefault      bool
	isExplicit     bool
	isUnresolvable bool
	parent         *Metadata
}

func NewMetadata(r Range, ref Reference) Metadata {
	if r == nil {
		panic("range is nil")
	}
	if ref == nil {
		panic("reference is nil")
	}
	return Metadata{
		rnge:      r,
		ref:       ref,
		isManaged: true,
	}
}

func (m Metadata) WithParent(p Metadata) Metadata {
	m.parent = &p
	return m
}

func (m Metadata) Parent() *Metadata {
	return m.parent
}

func (m Metadata) IsMultiLine() bool {
	return m.rnge.GetStartLine() < m.rnge.GetEndLine()
}

func NewUnmanagedMetadata() Metadata {
	m := NewMetadata(NewRange("", 0, 0), &FakeReference{})
	m.isManaged = false
	return m
}

func NewTestMetadata() Metadata {
	return NewMetadata(NewRange("test.test", 123, 123), &FakeReference{})
}

func (m Metadata) IsDefault() bool {
	return m.isDefault
}

func (m Metadata) IsExplicit() bool {
	return m.isExplicit
}

func (m Metadata) String() string {
	return m.ref.String()
}

func (m Metadata) Reference() Reference {
	return m.ref
}

func (m Metadata) Range() Range {
	if m.rnge == nil {
		return NewRange("unknown", 0, 0)
	}
	return m.rnge
}

func (m Metadata) IsManaged() bool {
	return m.isManaged
}

func (m Metadata) IsUnmanaged() bool {
	return !m.isManaged
}

type BaseAttribute struct {
	metadata Metadata
}

func (b BaseAttribute) GetMetadata() Metadata {
	return b.metadata
}

func (m Metadata) GetMetadata() Metadata {
	return m
}

func (m Metadata) GetRawValue() interface{} {
	return nil
}
