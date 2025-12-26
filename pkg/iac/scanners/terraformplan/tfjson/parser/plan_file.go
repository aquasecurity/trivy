package parser

type Resource struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
}

func (r Resource) BlockType() string {
	if r.Mode == "managed" {
		return "resource"
	}
	return r.Mode
}

type ResourceChange struct {
	Resource
	Change `json:"change"`
}

type ResourceExpressions map[string]any

type ConfigurationResource struct {
	Resource
	Expressions ResourceExpressions `json:"expressions"`
}

type Change struct {
	After map[string]any `json:"after"`
}

type Module struct {
	Resources    []Resource `json:"resources"`
	ChildModules []Module   `json:"child_modules"`
	// Omitted if the instance is in the root module.
	Address string `json:"address"`
}

type ConfigurationModule struct {
	Resources   []ConfigurationResource `json:"resources"`
	ModuleCalls map[string]CallModule   `json:"module_calls"`
}

type CallModule struct {
	Module ConfigurationModule `json:"module"`
}

type PlannedValues struct {
	RootModule Module `json:"root_module"`
}

type Configuration struct {
	RootModule ConfigurationModule `json:"root_module"`
}

type PlanFile struct {
	PlannedValues   PlannedValues    `json:"planned_values"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
	Configuration   Configuration    `json:"configuration"`
}
