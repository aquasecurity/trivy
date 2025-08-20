package parser

import (
	"errors"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/samber/lo"
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
	inner    taskInner
	rng      Range
	src      fsutils.FileSource
	metadata iacTypes.Metadata

	raw  map[string]*Node
	role *Role
	play *Play
}

type taskInner struct {
	Name  string    `yaml:"name"`
	Block []*Task   `yaml:"block"`
	Vars  vars.Vars `yaml:"vars"`
}

func (t *Task) UnmarshalYAML(node *yaml.Node) error {
	t.rng = rangeFromNode(node)

	var rawMap map[string]*Node
	if err := node.Decode(&rawMap); err != nil {
		return err
	}

	t.raw = rawMap
	return node.Decode(&t.inner)
}

func (t *Task) getPlay() *Play {
	if t.role != nil {
		return t.role.play
	}
	return t.play
}

func (t *Task) isBlock() bool {
	return len(t.inner.Block) > 0
}

func (t *Task) initMetadata(fileSrc fsutils.FileSource, parent *iacTypes.Metadata) {
	fsys, relPath := fileSrc.FSAndRelPath()
	ref := lo.Ternary(t.isBlock(), "tasks-block", "tasks")
	rng := iacTypes.NewRange(relPath, t.rng.startLine, t.rng.endLine, "", fsys)
	t.src = fileSrc
	t.metadata = iacTypes.NewMetadata(rng, ref)
	t.metadata.SetParentPtr(parent)

	for _, tt := range t.inner.Block {
		tt.src = fileSrc
		tt.play = t.play
		tt.metadata = iacTypes.NewMetadata(
			iacTypes.NewRange(relPath, tt.rng.startLine, tt.rng.endLine, "", fsys),
			"task",
		)
		tt.metadata.SetParentPtr(&t.metadata)
	}

	for _, n := range t.raw {
		if n == nil {
			continue
		}
		n.initMetadata(fileSrc, &t.metadata, nil)
	}
}

// hasModuleKey checks if the task has any of the given module keys in its raw map.
func (t *Task) hasModuleKey(modules []string) bool {
	for _, module := range modules {
		if _, exists := t.raw[module]; exists {
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
		m, err := task.ResolveModule(keys...)
		if err != nil {
			if errors.Is(err, ErrModuleNotFound) {
				continue
			}
			log.Debug("Failed to find module", log.Err(err))
			continue
		}
		modules = append(modules, m)
	}

	return modules
}

// ResolvedTask represents an Ansible task with all variables resolved.
//
// It holds only the essential data needed for execution and
// ensures the original Task remains unmodified.
type ResolvedTask struct {
	Name     string
	Fields   map[string]*Node
	Vars     vars.Vars
	Metadata iacTypes.Metadata
	Range    Range
}

var ErrModuleNotFound = errors.New("module not found")

// ResolveModule searches for the first module from given keys in task fields,
// renders its parameters using task variables, and returns the module.
// The module can be either structured (map of parameters) or free-form (string).
// Returns an error if no module is found or if rendering fails.
func (t *ResolvedTask) ResolveModule(keys ...string) (Module, error) {
	for _, key := range keys {
		f, exists := t.Fields[key]
		if !exists {
			continue
		}

		// TODO: cache the module?
		rendered, err := f.Render(t.Vars)
		if err != nil {
			return Module{}, xerrors.Errorf("render module parameters: %w", err)
		}
		switch v := rendered.val.(type) {
		case map[string]*Node:
			return Module{metadata: rendered.metadata, params: v}, nil
		case string:
			return Module{metadata: rendered.metadata, freeForm: v}, nil
		}
	}
	return Module{}, ErrModuleNotFound
}
