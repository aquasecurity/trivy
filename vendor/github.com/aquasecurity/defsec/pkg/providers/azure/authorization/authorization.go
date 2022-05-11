package authorization

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	types.Metadata
	Permissions      []Permission
	AssignableScopes []types.StringValue
}

type Permission struct {
	types.Metadata
	Actions []types.StringValue
}
