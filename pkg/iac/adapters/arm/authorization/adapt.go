package authorization

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) authorization.Authorization {
	return authorization.Authorization{
		RoleDefinitions: adaptRoleDefinitions(deployment),
		RoleAssignments: adaptRoleAssignments(deployment),
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

func adaptRoleAssignments(deployment azure.Deployment) (roleAssignments []authorization.RoleAssignment) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Authorization/roleAssignments") {
		roleAssignments = append(roleAssignments, adaptRoleAssignment(resource))
	}
	return roleAssignments
}

func adaptRoleAssignment(resource azure.Resource) authorization.RoleAssignment {
	return authorization.RoleAssignment{
		Metadata:         resource.Metadata,
		Scope:            resource.Properties.GetMapValue("scope").AsStringValue("", resource.Metadata),
		RoleDefinitionId: resource.Properties.GetMapValue("roleDefinitionId").AsStringValue("", resource.Metadata),
		PrincipalId:      resource.Properties.GetMapValue("principalId").AsStringValue("", resource.Metadata),
		PrincipalType:    resource.Properties.GetMapValue("principalType").AsStringValue("", resource.Metadata),
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
