package azure

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

type Deployment struct {
	Metadata    types.Metadata
	TargetScope Scope
	Parameters  []Parameter
	Variables   []Variable
	Resources   []Resource
	Outputs     []Output
}

type Parameter struct {
	Variable
	Default    Value
	Decorators []Decorator
}

type Variable struct {
	Name  string
	Value Value
}

type Output Variable

type Resource struct {
	Metadata   types.Metadata
	APIVersion Value
	Type       Value
	Kind       Value
	Name       Value
	Location   Value
	Tags       Value
	Sku        Value
	Properties Value
	Resources  []Resource
}

type PropertyBag struct {
	Metadata types.Metadata
	Data     map[string]Value
}

type Decorator struct {
	Name string
	Args []Value
}

type Scope string

const (
	ScopeResourceGroup Scope = "resourceGroup"
)

func (d *Deployment) GetResourcesByType(t string) []Resource {
	var resources []Resource
	for _, r := range d.Resources {
		if r.Type.AsString() == t {
			resources = append(resources, r)
		}
	}
	return resources
}

func (r *Resource) GetResourcesByType(t string) []Resource {
	var resources []Resource
	for _, res := range r.Resources {
		if res.Type.AsString() == t {
			resources = append(resources, res)
		}
	}
	return resources
}

func (d *Deployment) GetParameter(parameterName string) interface{} {

	for _, parameter := range d.Parameters {
		if parameter.Name == parameterName {
			return parameter.Value.Raw()
		}
	}
	return nil
}

func (d *Deployment) GetVariable(variableName string) interface{} {

	for _, variable := range d.Variables {
		if variable.Name == variableName {
			return variable.Value.Raw()
		}
	}
	return nil
}

func (d *Deployment) GetEnvVariable(envVariableName string) interface{} {

	if envVariable, exists := os.LookupEnv(envVariableName); exists {
		return envVariable
	}
	return nil
}

func (d *Deployment) GetOutput(outputName string) interface{} {

	for _, output := range d.Outputs {
		if output.Name == outputName {
			return output.Value.Raw()
		}
	}
	return nil
}

func (d *Deployment) GetDeployment() interface{} {

	type template struct {
		Schema         string                 `json:"$schema"`
		ContentVersion string                 `json:"contentVersion"`
		Parameters     map[string]interface{} `json:"parameters"`
		Variables      map[string]interface{} `json:"variables"`
		Resources      []interface{}          `json:"resources"`
		Outputs        map[string]interface{} `json:"outputs"`
	}

	type templateLink struct {
		URI string `json:"uri"`
	}

	type properties struct {
		TemplateLink      templateLink           `json:"templateLink"`
		Template          template               `json:"template"`
		TemplateHash      string                 `json:"templateHash"`
		Parameters        map[string]interface{} `json:"parameters"`
		Mode              string                 `json:"mode"`
		ProvisioningState string                 `json:"provisioningState"`
	}

	deploymentShell := struct {
		Name       string     `json:"name"`
		Properties properties `json:"properties"`
	}{
		Name: "Placeholder Deployment",
		Properties: properties{
			TemplateLink: templateLink{
				URI: "https://placeholder.com",
			},
			Template: template{
				Schema:         "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
				ContentVersion: "",
				Parameters:     make(map[string]interface{}),
				Variables:      make(map[string]interface{}),
				Resources:      make([]interface{}, 0),
				Outputs:        make(map[string]interface{}),
			},
		},
	}

	for _, parameter := range d.Parameters {
		deploymentShell.Properties.Template.Parameters[parameter.Name] = parameter.Value.Raw()
	}

	for _, variable := range d.Variables {
		deploymentShell.Properties.Template.Variables[variable.Name] = variable.Value.Raw()
	}

	for _, resource := range d.Resources {
		deploymentShell.Properties.Template.Resources = append(deploymentShell.Properties.Template.Resources, resource)
	}

	for _, output := range d.Outputs {
		deploymentShell.Properties.Template.Outputs[output.Name] = output.Value.Raw()
	}

	return deploymentShell
}
