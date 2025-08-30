package vars

import (
	"fmt"
	"maps"

	"github.com/aquasecurity/trivy/pkg/log"
)

// VarPriority represents the priority level of a variable.
// Higher values indicate higher precedence when merging variables.
type VarPriority int

const (
	RoleDefaultsPriority VarPriority = iota + 1
	InvFileGroupPriority
	InvExtAllGroupPriority
	PbExtAllGroupPriority
	InvExtGroupPriority
	PbExtGroupPriority
	InvFileHostPriority
	InvExtHostPriority
	PbExtHostPriority
	PlayVarsPriority
	PlayVarsFilesPriority
	RoleVarsPriority
	BlockVarsPriority
	TaskVarsPriority
	ExtraVarsPriority
	// Special variables cannot be set directly by the user;
	// Ansible will always override them to reflect internal state.
	SpecialVarsPriority
)

func (p VarPriority) Source() string {
	switch p {
	case RoleDefaultsPriority:
		return "role defaults"
	case InvFileGroupPriority:
		return "group vars (file)"
	case InvExtAllGroupPriority:
		return "group_vars/all (inv)"
	case PbExtAllGroupPriority:
		return "group_vars/all (pb)"
	case InvExtGroupPriority:
		return "group_vars/* (inv)"
	case PbExtGroupPriority:
		return "group_vars/* (pb)"
	case InvFileHostPriority:
		return "host vars (file)"
	case InvExtHostPriority:
		return "host_vars/* (inv)"
	case PbExtHostPriority:
		return "host_vars/* (pb)"
	case PlayVarsPriority:
		return "play"
	case PlayVarsFilesPriority:
		return "role (defaults)"
	case RoleVarsPriority:
		return "role"
	case BlockVarsPriority:
		return "block"
	case TaskVarsPriority:
		return "task"
	case ExtraVarsPriority:
		return "extra"
	case SpecialVarsPriority:
		return "special"
	default:
		return "unknown"
	}
}

var VarFilesExtensions = []string{"", ".yml", ".yaml", ".json"}

// Variable represents a variable with its value and priority.
type Variable struct {
	Value    any
	Priority VarPriority
}

func NewVariable(val any, priority VarPriority) Variable {
	return Variable{
		Value:    val,
		Priority: priority,
	}
}

// PlainVars is a simple map from variable names to their values.
type PlainVars map[string]any

// Vars represents a set of variables as a map from string keys to Variable.
type Vars map[string]Variable

// NewVars creates a Vars map from a plain map[string]any, assigning
// the given priority to each variable.
func NewVars(values PlainVars, priority VarPriority) Vars {
	v := make(Vars, len(values))
	for k, val := range values {
		v[k] = Variable{
			Value:    val,
			Priority: priority,
		}
	}
	return v
}

// ToPlain returns a plain map[string]any with only variable values,
// discarding Priority and Source information.
func (v Vars) ToPlain() map[string]any {
	plain := make(map[string]any, len(v))
	for k, variable := range v {
		plain[k] = variable.Value
	}
	return plain
}

// Clone creates a shallow copy of Vars.
func (v Vars) Clone() Vars {
	if v == nil {
		return nil
	}
	c := make(Vars, len(v))
	maps.Copy(c, v)
	return c
}

func MergeVars(varsList ...Vars) Vars {
	result := Vars{}
	for _, vars := range varsList {
		for k, newVar := range vars {
			if existing, ok := result[k]; ok {
				if newVar.Priority < existing.Priority {
					log.WithPrefix("ansible").Debug(
						fmt.Sprintf(
							"Overwriting variable %q from %s (priority %d) with value from %s (priority %d)",
							k,
							existing.Priority.Source(), existing.Priority,
							newVar.Priority.Source(), newVar.Priority,
						),
					)
				}
			}
			result[k] = newVar
		}
	}
	return result
}
