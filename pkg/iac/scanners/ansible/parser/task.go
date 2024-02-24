package parser

import (
	"fmt"
	"io/fs"

	"github.com/mitchellh/mapstructure"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	includeRoleAction  = "include_role"
	importRoleAction   = "import_role"
	includeTasksAction = "include_tasks"
	importTasksAction  = "import_tasks"
)

type Variables map[string]any

type Tasks []*Task

func (t Tasks) GetModules(names ...string) []Module {
	var modules []Module

	for _, task := range t {
		for _, name := range names {
			if module, exists := task.getModule(name); exists {
				modules = append(modules, module)
			}
		}
	}

	return modules
}

// RoleIncludeModule represents the "include_role" or "import_role" module
type RoleIncludeModule struct {
	Name         string `mapstructure:"name"`
	TasksFrom    string `mapstructure:"tasks_from"`
	DefaultsFrom string `mapstructure:"defaults_from"`
	VarsFrom     string `mapstructure:"vars_from"`
	Public       bool   `mapstructure:"public"`
}

// TaskIncludeModule represents the "include_tasks" or "import_tasks" module
type TaskIncludeModule struct {
	File string `mapstructure:"file"`
}

type Task struct {
	inner    taskInner
	rng      Range
	metadata iacTypes.Metadata

	raw  map[string]*Attribute
	role *Role
	play *Play
}

type taskInner struct {
	Name  string    `yaml:"name"`
	Block []*Task   `yaml:"block"`
	Vars  Variables `yaml:"vars"`
}

func (t *Task) UnmarshalYAML(node *yaml.Node) error {
	t.rng = rangeFromNode(node)

	var rawMap map[string]*Attribute
	if err := node.Decode(&rawMap); err != nil {
		return err
	}

	t.raw = rawMap
	if err := node.Decode(&t.inner); err != nil {
		return err
	}
	for _, b := range t.inner.Block {
		b.metadata.SetParentPtr(&t.metadata)
	}
	return nil
}

func (t *Task) name() string {
	return t.inner.Name
}

func (t *Task) path() string {
	return t.metadata.Range().GetFilename()
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

func (t *Task) getModule(name string) (Module, bool) {
	val, exists := t.raw[name]
	if !exists {
		return Module{}, false
	}

	if !val.IsMap() {
		return Module{}, false
	}

	params := val.AsMap()

	return Module{
		metadata: val.Metadata(),
		attrs:    params,
	}, true
}

func (t *Task) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	t.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, t.rng.startLine, t.rng.endLine, "", fsys),
		"task", // TODO add reference
	)
	t.metadata.SetParentPtr(parent)

	for _, attr := range t.raw {
		attr.updateMetadata(fsys, &t.metadata, path)
	}
}

// isModuleFreeForm determines whether a module parameter is defined as a free-form
// string value within the task's raw data.
//
// Example:
// - include_tasks: file.yml
// TODO: add test
func (t *Task) isModuleFreeForm(moduleName string) (string, bool) {
	param, exists := t.raw[moduleName]
	if !exists {
		return "", false
	}

	if param.IsString() {
		return *param.AsString(), true
	}

	return "", false
}

func (t *Task) actionOneOf(actions []string) bool {
	return lo.SomeBy(actions, func(action string) bool {
		_, exists := t.raw[action]
		return exists
	})
}

func (t *Task) isTaskInclude() bool {
	return t.actionOneOf(withBuiltinPrefix(importTasksAction, includeTasksAction))
}

func (t *Task) isRoleInclude() bool {
	return t.actionOneOf(withBuiltinPrefix(importRoleAction, includeRoleAction))
}

func (t *Task) getTaskInclude() (TaskIncludeModule, error) {
	var module TaskIncludeModule
	if err := t.getIncludeModule([]string{includeTasksAction, importTasksAction}, &module); err != nil {
		return TaskIncludeModule{}, err
	}
	return module, nil
}

func (t *Task) getRoleInclude() (RoleIncludeModule, error) {
	var module RoleIncludeModule
	if err := t.getIncludeModule([]string{includeRoleAction, importRoleAction}, &module); err != nil {
		return RoleIncludeModule{}, err
	}
	return module, nil
}

func (t *Task) getIncludeModule(actions []string, dst any) error {
	rawModule := make(map[string]string)
	for _, action := range withBuiltinPrefix(actions...) {
		if val, ok := t.isModuleFreeForm(action); ok {
			rawModule["file"] = val
		} else if val, ok := t.getModule(action); ok {
			rawModule = val.toStringMap()
		}
	}

	if err := mapstructure.Decode(rawModule, &dst); err != nil {
		return fmt.Errorf("failed to decode include module: %w", err)
	}

	return nil
}

func (t *Task) occurrences() []string {
	var occurrences []string

	mod := &t.metadata

	for {
		mod = mod.Parent()
		if mod == nil {
			break
		}
		parentRange := mod.Range()
		occurrences = append(occurrences, parentRange.GetFilename())
	}
	return occurrences
}
