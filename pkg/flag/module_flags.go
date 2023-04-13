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
	ModuleDirFlag = Flag{
		Name:       "module-dir",
		ConfigName: "module.dir",
		Value:      module.DefaultDir,
		Usage:      "specify directory to the wasm modules that will be loaded",
		Persistent: true,
	}
	EnableModulesFlag = Flag{
		Name:       "enable-modules",
		ConfigName: "module.enable-modules",
		Value:      []string{},
		Usage:      "[EXPERIMENTAL] module names to enable",
		Persistent: true,
	}
)

// ModuleFlagGroup defines flags for modules
type ModuleFlagGroup struct {
	Dir            *Flag
	EnabledModules *Flag
}

type ModuleOptions struct {
	ModuleDir      string
	EnabledModules []string
}

func NewModuleFlagGroup() *ModuleFlagGroup {
	return &ModuleFlagGroup{
		Dir:            &ModuleDirFlag,
		EnabledModules: &EnableModulesFlag,
	}
}

func (f *ModuleFlagGroup) Name() string {
	return "Module"
}

func (f *ModuleFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.Dir,
		f.EnabledModules,
	}
}

func (f *ModuleFlagGroup) ToOptions() ModuleOptions {
	return ModuleOptions{
		ModuleDir:      getString(f.Dir),
		EnabledModules: getStringSlice(f.EnabledModules),
	}
}
