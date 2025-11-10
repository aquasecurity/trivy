package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptGroups(modules terraform.Modules) []iam.Group {
	var groups []iam.Group

	for _, groupBlock := range modules.GetResourcesByType("aws_iam_group") {
		group := iam.Group{
			Metadata: groupBlock.GetMetadata(),
			Name:     groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock),
		}

		if policy, ok := applyForDependentResource(
			modules, groupBlock.ID(), "name", "aws_iam_group_policy", "group", findPolicy(modules),
		); ok && policy != nil {
			group.Policies = append(group.Policies, *policy)
		}

		if policy, ok := applyForDependentResource(
			modules, groupBlock.ID(), "name", "aws_iam_group_policy_attachment", "group", findAttachmentPolicy(modules),
		); ok && policy != nil {
			group.Policies = append(group.Policies, *policy)
		}

		groups = append(groups, group)
	}
	return groups
}
