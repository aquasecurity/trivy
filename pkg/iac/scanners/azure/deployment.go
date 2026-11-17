package azure

import (
	"slices"
	"strings"

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

// GetChildResources returns the resources of childType that belong to parent:
// the ones nested in parent at any depth, and the top-level ones whose name
// starts with the parent's name and "/". childType is either a full type or a
// type relative to the parent's, such as "blobServices/containers" for a
// storage account. Types match case-insensitively.
//
// The parser does not evaluate expressions, so a top-level resource is skipped
// when its name or the parent's name is an expression. GetOrphanResources
// returns it instead.
func (d *Deployment) GetChildResources(parent Resource, childType string) []Resource {
	parentType := parent.Type.AsString()
	fullType := qualifyType(parentType, childType)
	resources := nestedResources(parent.Resources, parentType, fullType)
	for _, resource := range d.Resources {
		if strings.EqualFold(resource.Type.AsString(), fullType) && isNamedChild(resource, parent) {
			resources = append(resources, resource)
		}
	}
	return resources
}

// GetOrphanResources returns the top-level resources of childType that
// GetChildResources returns for no top-level resource of parentType.
func (d *Deployment) GetOrphanResources(parentType, childType string) []Resource {
	fullType := qualifyType(parentType, childType)
	parents := d.GetResourcesByType(parentType)
	var orphans []Resource
	for _, resource := range d.Resources {
		if !strings.EqualFold(resource.Type.AsString(), fullType) {
			continue
		}
		if !slices.ContainsFunc(parents, func(parent Resource) bool { return isNamedChild(resource, parent) }) {
			orphans = append(orphans, resource)
		}
	}
	return orphans
}

func nestedResources(resources []Resource, parentType, fullType string) []Resource {
	var found []Resource
	for _, resource := range resources {
		typ := qualifyType(parentType, resource.Type.AsString())
		if strings.EqualFold(typ, fullType) {
			found = append(found, resource)
		}
		found = append(found, nestedResources(resource.Resources, typ, fullType)...)
	}
	return found
}

// qualifyType returns the full type of a resource declared with typ under a
// parent of parentType. A full type starts with a resource provider namespace,
// such as Microsoft.Storage, and only namespaces contain a dot.
func qualifyType(parentType, typ string) string {
	namespace, _, _ := strings.Cut(typ, "/")
	if strings.Contains(namespace, ".") {
		return typ
	}
	return parentType + "/" + typ
}

func isNamedChild(child, parent Resource) bool {
	childName, parentName := child.Name.AsString(), parent.Name.AsString()
	if childName == "" || parentName == "" {
		return false
	}
	prefix := parentName + "/"
	return len(childName) > len(prefix) && strings.EqualFold(childName[:len(prefix)], prefix)
}
