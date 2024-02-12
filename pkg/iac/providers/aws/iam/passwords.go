package iam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type PasswordPolicy struct {
	Metadata             defsecTypes.Metadata
	ReusePreventionCount defsecTypes.IntValue
	RequireLowercase     defsecTypes.BoolValue
	RequireUppercase     defsecTypes.BoolValue
	RequireNumbers       defsecTypes.BoolValue
	RequireSymbols       defsecTypes.BoolValue
	MaxAgeDays           defsecTypes.IntValue
	MinimumLength        defsecTypes.IntValue
}
