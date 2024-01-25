package authorization

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	Metadata         defsecTypes.MisconfigMetadata
	Permissions      []Permission
	AssignableScopes []defsecTypes.StringValue
}

type Permission struct {
	Metadata defsecTypes.MisconfigMetadata
	Actions  []defsecTypes.StringValue
}
