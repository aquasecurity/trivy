package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptRoles(modules terraform.Modules) []iam.Role {
	var roles []iam.Role
	for _, roleBlock := range modules.GetResourcesByType("aws_iam_role") {
		role := iam.Role{
			Metadata: roleBlock.GetMetadata(),
			Name:     roleBlock.GetAttribute("name").AsStringValueOrDefault("", roleBlock),
		}

		if inlineBlock := roleBlock.GetBlock("inline_policy"); inlineBlock.IsNotNil() {
			if policy, err := parsePolicy(inlineBlock, modules); err == nil {
				role.Policies = append(role.Policies, policy)
			}
		}

		if policy, ok := applyForDependentResource(
			modules, roleBlock.ID(), "name", "aws_iam_role_policy", "role", findPolicy(modules),
		); ok && policy != nil {
			role.Policies = append(role.Policies, *policy)
		}

		if policy, ok := applyForDependentResource(
			modules, roleBlock.ID(), "name", "aws_iam_role_policy_attachment", "role", findAttachmentPolicy(modules),
		); ok && policy != nil {
			role.Policies = append(role.Policies, *policy)
		}

		roles = append(roles, role)
	}

	return roles
}
