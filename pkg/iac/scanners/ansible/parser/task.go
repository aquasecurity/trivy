package parser

import (
	"io/fs"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	ModuleIncludeRole  = "include_role"
	ModuleImportRole   = "import_role"
	ModuleIncludeTasks = "include_tasks"
	ModuleImportTasks  = "import_tasks"
)

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
	metadata iacTypes.Metadata

	raw  map[string]*Attribute
	role *Role
	play *Play
}

type taskInner struct {
	Name  string  `yaml:"name"`
	Block []*Task `yaml:"block"`
	Vars  Vars    `yaml:"vars"`
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

func (t *Task) Name() string {
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

func (t *Task) initMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	t.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, t.rng.startLine, t.rng.endLine, "", fsys),
		"task", // TODO add reference
	)
	t.metadata.SetParentPtr(parent)

	for _, attr := range t.raw {
		// TODO: parse null attributes
		if attr == nil {
			continue
		}
		attr.updateMetadata(fsys, &t.metadata, path)
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

// decodeModuleParams searches for the first module name from the list (with or without builtin prefix)
// present in the task's raw data and decodes its parameters into dst.
//
// Supports both free-form string syntax and map-style syntax for module parameters.
func (t *Task) decodeModuleParams(modules []string, dst any) error {
	rawModule := make(map[string]string)
	for _, key := range modules {
		if val, ok := t.getModuleFreeFormParam(key); ok {
			rawModule["file"] = val
			break
		} else if val, ok := t.getModule(key); ok {
			rawModule = val.toStringMap()
			break
		}
	}

	if len(rawModule) == 0 {
		return xerrors.New("module data not found")
	}

	if err := mapstructure.Decode(rawModule, &dst); err != nil {
		return xerrors.Errorf("decode module: %w", err)
	}

	return nil
}

// getModuleFreeFormParam checks if the module parameter is specified as a free-form string
// in the task's raw data, returning the string value if present.
//
// A free-form parameter means the module is used with a single string argument
// instead of a key-value map. For example:
//
//   - include_tasks: file.yml
//
// Here, "file.yml" is a free-form string parameter passed directly to the module.
//
// TODO: add unit test for this case
func (t *Task) getModuleFreeFormParam(moduleName string) (string, bool) {
	param, exists := t.raw[moduleName]
	if !exists {
		return "", false
	}

	if param.IsString() {
		return *param.AsString(), true
	}

	return "", false
}
