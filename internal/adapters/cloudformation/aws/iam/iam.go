package iam

import (
	"github.com/aquasecurity/trivy/pkg/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) iam.IAM {
	return iam.IAM{
		PasswordPolicy: iam.PasswordPolicy{
			Metadata:             defsecTypes.NewUnmanagedMisconfigMetadata(),
			ReusePreventionCount: defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMisconfigMetadata()),
			RequireLowercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
			RequireUppercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
			RequireNumbers:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
			RequireSymbols:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
			MaxAgeDays:           defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMisconfigMetadata()),
			MinimumLength:        defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMisconfigMetadata()),
		},
		Policies: getPolicies(cfFile),
		Groups:   getGroups(cfFile),
		Users:    getUsers(cfFile),
		Roles:    getRoles(cfFile),
	}
}
