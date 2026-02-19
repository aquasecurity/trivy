package eval

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

type Address interface {
	Key() string
}

type ForEachAddr struct{ Name string }

func (r ForEachAddr) Key() string { return "each." + r.Name }

type CountAddr struct{ Name string }

func (r CountAddr) Key() string { return "count." + r.Name }

type LocalAddr struct{ Name string }

func (r LocalAddr) Key() string { return "locals." + r.Name }

type VariableAddr struct{ Name string }

func (r VariableAddr) Key() string { return "variable." + r.Name }

type OutputAddr struct{ Name string }

func (r OutputAddr) Key() string { return "output." + r.Name }

type ProviderAddr struct{ Name string }

func (r ProviderAddr) Key() string { return "provider." + r.Name }

type ModuleCallAddr struct {
	Name string
}

func (r ModuleCallAddr) Key() string {
	return "module." + r.Name
}

type ModuleCallOutputAddr struct {
	Call ModuleCallAddr
	Name string
}

func (a ModuleCallOutputAddr) Key() string { return a.Call.Key() + ".output." + a.Name }

type ResourceMode int

const (
	UnknownMode ResourceMode = iota
	DataMode
	ManagedMode
)

func modeByBlockType(blockType string) ResourceMode {
	switch blockType {
	case "resource":
		return ManagedMode
	case "data":
		return DataMode
	default:
		return UnknownMode
	}
}

type ResourceAddr struct {
	Mode       ResourceMode
	Type, Name string
}

func (a ResourceAddr) Key() string {
	switch a.Mode {
	case ManagedMode:
		return "resource." + a.Type + "." + a.Name
	case DataMode:
		return "data." + a.Type + "." + a.Name
	default:
		panic(fmt.Sprintf("unexpected resource mode: %d", a.Mode))
	}
}

func (a ResourceAddr) Instance(key InstanceKey) ResourceInstanceAddr {
	return ResourceInstanceAddr{
		Resource: a,
		Index:    key,
	}
}

type ResourceInstanceAddr struct {
	Resource ResourceAddr
	Index    InstanceKey
}

func (r ResourceInstanceAddr) Key() string {
	k := r.Resource.Key()
	if r.Index != NoKey {
		k += r.Key()
	}
	return k
}

var RootModule ModuleAddr

type ModuleAddr []string

func (a ModuleAddr) IsRoot() bool { return len(a) == 0 }

func (a ModuleAddr) Equal(other ModuleAddr) bool {
	return slices.Equal(a, other)
}

func (a ModuleAddr) Key() string {
	if a.IsRoot() {
		return ""
	}
	parts := make([]string, 0, len(a)*2)
	for _, step := range a {
		parts = append(parts, "module", step)
	}
	return strings.Join(parts, ".")
}

func (a ModuleAddr) Parent() ModuleAddr {
	if a.IsRoot() {
		panic("module is root")
	}
	return slices.Clone(a[:len(a)-1])
}

func (a ModuleAddr) Call(name string) ModuleAddr {
	cloned := slices.Clone(a)
	cloned = append(cloned, name)
	return cloned
}

func (m ModuleAddr) BlockAddr(blockAddr Address) InModuleAddress {
	return InModuleAddress{
		Module: m,
		Block:  blockAddr,
	}
}

type InModuleAddress struct {
	Module ModuleAddr
	Block  Address
}

func (r InModuleAddress) Key() string {
	if len(r.Module) == 0 {
		return r.Block.Key()
	}
	return r.Module.Key() + "." + r.Block.Key()
}

var RootModuleInstanceAddr ModuleInstanceAddr

type ModuleInstanceAddr []ModuleAddrStep

func (a ModuleInstanceAddr) IsRoot() bool {
	return len(a) == 0
}

func (a ModuleInstanceAddr) Key() string {
	if a.IsRoot() {
		return ""
	}

	parts := make([]string, len(a)*2)
	for _, step := range a {
		name := step.Name
		if step.Key != NoKey {
			name += step.Key.String()
		}
		parts = append(parts, "module", name)
	}
	return strings.Join(parts, ".")
}

func (a ModuleInstanceAddr) Module() ModuleAddr {
	mod := make(ModuleAddr, 0, len(a))
	for _, step := range a {
		mod = append(mod, step.Name)
	}
	return mod
}

func (a ModuleInstanceAddr) Parent() ModuleInstanceAddr {
	if a.IsRoot() {
		panic("instacne is root")
	}

	return a[:len(a)-1]
}

func (a ModuleInstanceAddr) Last() ModuleAddrStep {
	if a.IsRoot() {
		panic("instance is root")
	}
	return a[len(a)-1]
}

func (a ModuleInstanceAddr) Child(name string, key InstanceKey) ModuleInstanceAddr {
	steps := slices.Clone(a)
	steps = append(steps, ModuleAddrStep{
		Name: name,
		Key:  key,
	})
	return steps
}

type ModuleAddrStep struct {
	Name string
	Key  InstanceKey
}

type InstanceKey interface {
	String() string
	Value() cty.Value
}

var NoKey InstanceKey

type IntKey int

func (k IntKey) String() string {
	return "[" + strconv.Itoa(int(k)) + "]"
}

func (k IntKey) Value() cty.Value {
	return cty.NumberIntVal(int64(k))
}

type StringKey string

func (k StringKey) String() string {
	return "[\"" + string(k) + "\"]"
}

func (k StringKey) Value() cty.Value {
	return cty.StringVal(string(k))
}
