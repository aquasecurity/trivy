package parser

type Resource struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	ProviderName  string `json:"provider_name"`
	SchemaVersion int    `json:"schema_version"`
}

type ResourceChange struct {
	Resource
	Change `json:"change"`
}

type ConfigurationResource struct {
	Resource
	Expressions map[string]interface{} `json:"expressions"`
}

type Change struct {
	Before map[string]interface{} `json:"before"`
	After  map[string]interface{} `json:"after"`
}

type Module struct {
	Resources    []Resource    `json:"resources"`
	ChildModules []ChildModule `json:"child_modules"`
}

type ChildModule struct {
	Module
	Address string `json:"address"`
}

type ConfigurationModule struct {
	Resources   []ConfigurationResource `json:"resources"`
	ModuleCalls map[string]CallModule   `json:"module_calls"`
}

type CallModule struct {
	Source string              `json:"source"`
	Module ConfigurationModule `json:"module"`
}

type ConfigurationChildModule struct {
	ConfigurationModule
	Address string `json:"address"`
}

type PlannedValues struct {
	RootModule Module `json:"root_module"`
}

type Configuration struct {
	RootModule ConfigurationModule `json:"root_module"`
}

type PlanFile struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	PlannedValues    PlannedValues    `json:"planned_values"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
	Configuration    Configuration    `json:"configuration"`
}
