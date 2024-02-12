package authorization

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	Metadata         defsecTypes.Metadata
	Permissions      []Permission
	AssignableScopes []defsecTypes.StringValue
}

type Permission struct {
	Metadata defsecTypes.Metadata
	Actions  []defsecTypes.StringValue
}
