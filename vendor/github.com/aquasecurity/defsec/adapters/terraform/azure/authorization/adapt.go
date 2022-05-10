package authorization

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/authorization"
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
		var actionsVal []types.StringValue
		actions := actionsAttr.ValueAsStrings()
		for _, action := range actions {
			actionsVal = append(actionsVal, types.String(action, permissionsBlock.GetMetadata()))
		}
		permissionsVal = append(permissionsVal, authorization.Permission{
			Metadata: permissionsBlock.GetMetadata(),
			Actions:  actionsVal,
		})
	}

	assignableScopesAttr := resource.GetAttribute("assignable_scopes")
	var assignableScopesVal []types.StringValue
	assignableScopes := assignableScopesAttr.ValueAsStrings()
	for _, scope := range assignableScopes {
		assignableScopesVal = append(assignableScopesVal, types.String(scope, resource.GetMetadata()))
	}

	return authorization.RoleDefinition{
		Metadata:         resource.GetMetadata(),
		Permissions:      permissionsVal,
		AssignableScopes: assignableScopesVal,
	}
}
