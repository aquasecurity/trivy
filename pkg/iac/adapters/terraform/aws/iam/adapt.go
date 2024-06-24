package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
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
