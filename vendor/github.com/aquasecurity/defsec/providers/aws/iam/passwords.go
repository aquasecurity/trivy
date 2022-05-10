package iam

import "github.com/aquasecurity/defsec/parsers/types"

type PasswordPolicy struct {
	types.Metadata
	ReusePreventionCount types.IntValue
	RequireLowercase     types.BoolValue
	RequireUppercase     types.BoolValue
	RequireNumbers       types.BoolValue
	RequireSymbols       types.BoolValue
	MaxAgeDays           types.IntValue
	MinimumLength        types.IntValue
}
