package terraform

import "errors"

type Type struct {
	name                  string
	refName               string
	removeTypeInReference bool
}

func (t Type) Name() string {
	return t.name
}

func (t Type) ShortName() string {
	if t.refName != "" {
		return t.refName
	}
	return t.name
}

var TypeCheck = Type{
	name: "check",
}

var TypeData = Type{
	name: "data",
}

var TypeResource = Type{
	name:                  "resource",
	removeTypeInReference: true,
}

var TypeVariable = Type{
	name:    "variable",
	refName: "var",
}

var TypeImport = Type{
	name: "import",
}

var TypeLocal = Type{
	name:    "locals",
	refName: "local",
}

var TypeMoved = Type{
	name: "moved",
}

var TypeProvider = Type{
	name: "provider",
}

var TypeOutput = Type{
	name: "output",
}

var TypeModule = Type{
	name: "module",
}

var TypeTerraform = Type{
	name: "terraform",
}

var ValidTypes = []Type{
	TypeCheck,
	TypeData,
	TypeImport,
	TypeLocal,
	TypeModule,
	TypeMoved,
	TypeOutput,
	TypeProvider,
	TypeResource,
	TypeTerraform,
	TypeVariable,
}

func IsValidType(name string) bool {
	for _, valid := range ValidTypes {
		if valid.name == name {
			return true
		}
	}
	return false
}

func IsValidBlockReference(name string) bool {
	for _, valid := range ValidTypes {
		if valid.refName == name {
			return true
		}
	}
	return false
}

func TypeFromRefName(name string) (*Type, error) {
	for _, valid := range ValidTypes {
		if valid.refName == name || (valid.refName == "" && valid.name == name) {
			return &valid, nil
		}
	}
	return nil, errors.New("block type not found")
}
