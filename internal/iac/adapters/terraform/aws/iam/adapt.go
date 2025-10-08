package iam

import (
	"github.com/aquasecurity/trivy/internal/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
)

func Adapt(modules terraform.Modules) iam.IAM {
	return iam.IAM{
		PasswordPolicy: adaptPasswordPolicy(modules),
		Policies:       adaptPolicies(modules),
		Groups:         adaptGroups(modules),
		Users:          adaptUsers(modules),
		Roles:          adaptRoles(modules),
	}
}
