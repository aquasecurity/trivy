package iam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type PasswordPolicy struct {
	Metadata             defsecTypes.MisconfigMetadata
	ReusePreventionCount defsecTypes.IntValue
	RequireLowercase     defsecTypes.BoolValue
	RequireUppercase     defsecTypes.BoolValue
	RequireNumbers       defsecTypes.BoolValue
	RequireSymbols       defsecTypes.BoolValue
	MaxAgeDays           defsecTypes.IntValue
	MinimumLength        defsecTypes.IntValue
}
