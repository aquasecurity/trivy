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

// GetChildResources returns the resources of childType under parent. It
// searches parent and the top-level resources named "<parent>/...", including
// everything nested in them. childType is a full type or one relative to the
// parent's type, such as "blobServices/containers". Types match
// case-insensitively.
//
// GetChildResources skips a top-level resource when its name or the parent's
// name is an expression, because the parser does not evaluate expressions.
func (d *Deployment) GetChildResources(parent Resource, childType string) []Resource {
	parentType := parent.Type.AsString()
	fullType := qualifyType(parentType, childType)
	resources := nestedResources(parent.Resources, parentType, fullType)
	for _, resource := range d.Resources {
		if isSubpath(resource.Type.AsString(), parentType) &&
			isSubpath(resource.Name.AsString(), parent.Name.AsString()) {
			resources = append(resources, nestedResources([]Resource{resource}, parentType, fullType)...)
		}
	}
	return resources
}

// GetOrphanResources returns the resources of childType whose parent of
// parentType is not found in the deployment, for example because the name of
// the child or the parent is an expression. childType is either a full type or
// a type relative to parentType.
func (d *Deployment) GetOrphanResources(parentType, childType string) []Resource {
	fullType := qualifyType(parentType, childType)
	parents := d.GetResourcesByType(parentType)
	var orphans []Resource
	for _, resource := range d.Resources {
		if !isSubpath(resource.Type.AsString(), parentType) {
			continue
		}
		hasParent := slices.ContainsFunc(parents, func(parent Resource) bool {
			return isSubpath(resource.Name.AsString(), parent.Name.AsString())
		})
		if !hasParent {
			orphans = append(orphans, nestedResources([]Resource{resource}, parentType, fullType)...)
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

// isSubpath reports whether path continues parent with "/" and at least one
// more character, ignoring case. An empty parent, such as the name of an
// expression, contains no paths.
func isSubpath(path, parent string) bool {
	prefix := parent + "/"
	return parent != "" && len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix)
}
