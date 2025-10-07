package authorization

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) authorization.Authorization {
	return authorization.Authorization{
		RoleDefinitions: adaptRoleDefinitions(deployment),
	}
}

func adaptRoleDefinitions(deployment azure.Deployment) (roleDefinitions []authorization.RoleDefinition) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Authorization/roleDefinitions") {
		roleDefinitions = append(roleDefinitions, adaptRoleDefinition(resource))
	}
	return roleDefinitions
}

func adaptRoleDefinition(resource azure.Resource) authorization.RoleDefinition {

	return authorization.RoleDefinition{
		Metadata:         resource.Metadata,
		Permissions:      adaptPermissions(resource),
		AssignableScopes: resource.Properties.GetMapValue("assignableScopes").AsStringValuesList(""),
	}
}

func adaptPermissions(resource azure.Resource) (permissions []authorization.Permission) {
	for _, permission := range resource.Properties.GetMapValue("permissions").AsList() {
		permissions = append(permissions, authorization.Permission{
			Metadata: resource.Metadata,
			Actions:  permission.GetMapValue("actions").AsStringValuesList(""),
		})
	}
	return permissions
}
