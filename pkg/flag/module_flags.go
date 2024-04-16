package flag

import (
	"github.com/aquasecurity/trivy/pkg/module"
)

// e.g. config yaml
// module:
//   dir: "/path/to/my_modules"
//   enable-modules:
//     - spring4shell

var (
	ModuleDirFlag = Flag[string]{
		Name:       "module-dir",
		ConfigName: "module.dir",
		Default:    module.DefaultDir,
		Usage:      "specify directory to the wasm modules that will be loaded",
		Persistent: true,
	}
	EnableModulesFlag = Flag[[]string]{
		Name:       "enable-modules",
		ConfigName: "module.enable-modules",
		Default:    []string{},
		Usage:      "[EXPERIMENTAL] module names to enable",
		Persistent: true,
	}
)

// ModuleFlagGroup defines flags for modules
type ModuleFlagGroup struct {
	Dir            *Flag[string]
	EnabledModules *Flag[[]string]
}

type ModuleOptions struct {
	ModuleDir      string
	EnabledModules []string
}

func NewModuleFlagGroup() *ModuleFlagGroup {
	return &ModuleFlagGroup{
		Dir:            ModuleDirFlag.Clone(),
		EnabledModules: EnableModulesFlag.Clone(),
	}
}

func (f *ModuleFlagGroup) Name() string {
	return "Module"
}

func (f *ModuleFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Dir,
		f.EnabledModules,
	}
}

func (f *ModuleFlagGroup) ToOptions() (ModuleOptions, error) {
	if err := parseFlags(f); err != nil {
		return ModuleOptions{}, err
	}

	return ModuleOptions{
		ModuleDir:      f.Dir.Value(),
		EnabledModules: f.EnabledModules.Value(),
	}, nil
}
