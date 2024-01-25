package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) iam.IAM {
	return iam.IAM{
		PasswordPolicy: iam.PasswordPolicy{
			Metadata:             defsecTypes.NewUnmanagedMetadata(),
			ReusePreventionCount: defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
			RequireLowercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			RequireUppercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			RequireNumbers:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			RequireSymbols:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			MaxAgeDays:           defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
			MinimumLength:        defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
		},
		Policies: getPolicies(cfFile),
		Groups:   getGroups(cfFile),
		Users:    getUsers(cfFile),
		Roles:    getRoles(cfFile),
	}
}
