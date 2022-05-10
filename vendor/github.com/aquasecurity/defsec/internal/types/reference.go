package types

type Reference interface {
	String() string
	LogicalID() string
	RefersTo(r Reference) bool
}

type FakeReference struct {
}

func (f *FakeReference) String() string {
	return ""
}

func (f *FakeReference) RefersTo(r Reference) bool {
	return false
}

func (f *FakeReference) LogicalID() string {
	return ""
}

type NamedReference struct {
	name string
}

func NewNamedReference(name string) Reference {
	return &NamedReference{name: name}
}

func (f *NamedReference) String() string {
	return f.name
}

func (f *NamedReference) RefersTo(r Reference) bool {
	return false
}

func (f *NamedReference) LogicalID() string {
	return f.String()
}
