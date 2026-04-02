package authorization

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
	RoleAssignments []RoleAssignment
}

type RoleDefinition struct {
	Metadata         iacTypes.Metadata
	Permissions      []Permission
	AssignableScopes []iacTypes.StringValue
}

type RoleAssignment struct {
	Metadata           iacTypes.Metadata
	RoleDefinitionId   iacTypes.StringValue
	RoleDefinitionName iacTypes.StringValue
	PrincipalId        iacTypes.StringValue
	PrincipalType      iacTypes.StringValue
}

type Permission struct {
	Metadata iacTypes.Metadata
	Actions  []iacTypes.StringValue
}
