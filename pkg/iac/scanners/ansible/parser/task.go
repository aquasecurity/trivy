package parser

import (
	"errors"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/orderedmap"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

const (
	ModuleIncludeRole  = "include_role"
	ModuleImportRole   = "import_role"
	ModuleIncludeTasks = "include_tasks"
	ModuleImportTasks  = "import_tasks"
)

// RoleIncludeModule represents the "include_role" or "import_role" module
type RoleIncludeModule struct {
	Name         string
	TasksFrom    string
	DefaultsFrom string
	VarsFrom     string
}

// Task represents a single Ansible task.
//
// A task defines a single unit of work, which may include running a module,
// calling a role, or including other task files.
//
// Tasks can contain parameters, conditions (when), loops, and other
// Ansible constructs.
//
// Example task:
//
//   - name: Install nginx
//     apt:
//     name: nginx
//     state: present
type Task struct {
	inner taskInner
	raw   orderedmap.OrderedMap[string, *Node]

	rng      Range
	src      fsutils.FileSource
	metadata iacTypes.Metadata

	role *Role
	play *Play
}

func (t *Task) Variables() vars.Vars {
	if t.isBlock() {
		return vars.NewVars(t.inner.Vars, vars.BlockVarsPriority)
	}
	return vars.NewVars(t.inner.Vars, vars.TaskVarsPriority)
}

type taskInner struct {
	Name  string         `yaml:"name"`
	Block []*Task        `yaml:"block"`
	Vars  vars.PlainVars `yaml:"vars"`
}

func (t *Task) UnmarshalYAML(node *yaml.Node) error {
	t.rng = rangeFromNode(node)

	var rawMap orderedmap.OrderedMap[string, *Node]
	if err := node.Decode(&rawMap); err != nil {
		return err
	}

	t.raw = rawMap
	return node.Decode(&t.inner)
}

func (t *Task) isBlock() bool {
	return len(t.inner.Block) > 0
}

func (t *Task) init(play *Play, fileSrc fsutils.FileSource, parent *iacTypes.Metadata) {
	fsys, relPath := fileSrc.FSAndRelPath()
	ref := lo.Ternary(t.isBlock(), "tasks-block", "tasks")
	rng := iacTypes.NewRange(relPath, t.rng.Start, t.rng.End, "", fsys)
	t.play = play
	t.src = fileSrc
	t.metadata = iacTypes.NewMetadata(rng, ref)
	t.metadata.SetParentPtr(parent)

	for _, tt := range t.inner.Block {
		tt.init(play, fileSrc, parent)
	}

	for _, n := range t.raw.Iter() {
		if n == nil {
			continue
		}
		n.initMetadata(fileSrc, &t.metadata, nil)
	}
}

// hasModuleKey checks if the task has any of the given module keys in its raw map.
func (t *Task) hasModuleKey(keys []string) bool {
	for _, module := range keys {
		if _, exists := t.raw.Get(module); exists {
			return true
		}
	}
	return false
}

// isTaskInclude returns true if the task includes or imports other tasks (task include modules).
func (t *Task) isTaskInclude() bool {
	return t.hasModuleKey(withBuiltinPrefix(ModuleImportTasks, ModuleIncludeTasks))
}

// isRoleInclude returns true if the task includes or imports a role (role include modules).
func (t *Task) isRoleInclude() bool {
	return t.hasModuleKey(withBuiltinPrefix(ModuleImportRole, ModuleIncludeRole))
}

func (t *Task) resolved(variables vars.Vars) *ResolvedTask {
	if variables == nil {
		variables = make(vars.Vars)
	}
	resolved := &ResolvedTask{
		Name:     t.inner.Name,
		Metadata: t.metadata,
		Vars:     variables,
		Range:    t.rng,
		Fields:   t.raw,
	}

	return resolved
}

type ResolvedTasks []*ResolvedTask

func (t ResolvedTasks) GetModules(keys ...string) []Module {
	var modules []Module

	for _, task := range t {
		m, err := task.ResolveModule(keys, false)
		if err != nil {
			if errors.Is(err, ErrModuleNotFound) {
				continue
			}
			log.WithPrefix("ansible").Debug("Failed to find module", log.Err(err))
			continue
		}
		modules = append(modules, m)
	}

	return modules
}

func (t ResolvedTasks) FilterByState(exclude ...string) ResolvedTasks {
	excludeSet := set.New(exclude...)
	return lo.Filter(t, func(task *ResolvedTask, _ int) bool {
		state, exists := task.Fields.Get("state")
		if !exists || state == nil || !state.IsKnown() {
			return true
		}
		if v, ok := state.AsString(); ok && excludeSet.Contains(v) {
			return false
		}
		return true
	})
}

// ResolvedTask represents an Ansible task with all variables resolved.
//
// It holds only the essential data needed for execution and
// ensures the original Task remains unmodified.
type ResolvedTask struct {
	Name   string
	Fields orderedmap.OrderedMap[string, *Node]
	Vars   vars.Vars

	Metadata iacTypes.Metadata
	Range    Range
}

var ErrModuleNotFound = errors.New("module not found")

// ResolveModule searches for the first module from given keys in task fields,
// renders its parameters using task variables, and returns the module.
// The module can be either structured (map of parameters) or free-form (string).
// Returns an error if no module is found or if rendering fails.
func (t *ResolvedTask) ResolveModule(keys []string, strict bool) (Module, error) {
	for _, key := range keys {
		f, exists := t.Fields.Get(key)
		if !exists {
			continue
		}

		// TODO: cache the module?
		rendered, err := f.Render(t.Vars)
		if err != nil {
			if strict {
				return Module{}, xerrors.Errorf("render: %w", err)
			}
			log.WithPrefix("ansible").Debug("Failed to render module params",
				log.String("source", t.Metadata.Range().String()),
				log.Err(err))
		}
		return Module{Node: rendered, Name: key}, nil
	}
	return Module{}, ErrModuleNotFound
}

func (t *ResolvedTask) MarshalYAML() (any, error) {
	out := make(map[string]any, t.Fields.Len())
	for fieldName, field := range t.Fields.Iter() {
		rendered, _ := field.Render(t.Vars)
		out[fieldName] = rendered.val
	}
	return out, nil
}

func (t *ResolvedTask) GetFieldsByRange(r Range) map[string]*Node {
	out := make(map[string]*Node)
	for key, node := range t.Fields.Iter() {
		if node == nil {
			continue
		}
		sub := node.Subtree(r)
		if sub != nil {
			out[key], _ = sub.Render(t.Vars)
		}
	}
	return out
}
