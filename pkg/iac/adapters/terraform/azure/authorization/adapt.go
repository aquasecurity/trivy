package authorization

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) authorization.Authorization {
	return authorization.Authorization{
		RoleDefinitions: adaptRoleDefinitions(modules),
	}
}

func adaptRoleDefinitions(modules terraform.Modules) []authorization.RoleDefinition {
	var roleDefinitions []authorization.RoleDefinition
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_role_definition") {
			roleDefinitions = append(roleDefinitions, adaptRoleDefinition(resource))
		}
	}
	return roleDefinitions
}

func adaptRoleDefinition(resource *terraform.Block) authorization.RoleDefinition {
	permissionsBlocks := resource.GetBlocks("permissions")
	var permissionsVal []authorization.Permission

	for _, permissionsBlock := range permissionsBlocks {
		actionsAttr := permissionsBlock.GetAttribute("actions")
		permissionsVal = append(permissionsVal, authorization.Permission{
			Metadata: permissionsBlock.GetMetadata(),
			Actions:  actionsAttr.AsStringValues(),
		})
	}

	assignableScopesAttr := resource.GetAttribute("assignable_scopes")
	return authorization.RoleDefinition{
		Metadata:         resource.GetMetadata(),
		Permissions:      permissionsVal,
		AssignableScopes: assignableScopesAttr.AsStringValues(),
	}
}
