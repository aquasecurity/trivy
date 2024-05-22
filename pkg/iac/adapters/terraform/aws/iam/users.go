package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptUsers(modules terraform.Modules) []iam.User {
	var users []iam.User

	for _, userBlock := range modules.GetResourcesByType("aws_iam_user") {
		user := iam.User{
			Metadata:   userBlock.GetMetadata(),
			Name:       userBlock.GetAttribute("name").AsStringValueOrDefault("", userBlock),
			LastAccess: iacTypes.TimeUnresolvable(userBlock.GetMetadata()),
		}

		if policy, ok := applyForDependentResource(
			modules, userBlock.ID(), "name", "aws_iam_user_policy", "user", findPolicy(modules),
		); ok && policy != nil {
			user.Policies = append(user.Policies, *policy)
		}

		if policy, ok := applyForDependentResource(
			modules, userBlock.ID(), "name", "aws_iam_user_policy_attachment", "user", findAttachmentPolicy(modules),
		); ok && policy != nil {
			user.Policies = append(user.Policies, *policy)
		}

		if accessKey, ok := applyForDependentResource(
			modules, userBlock.ID(), "name", "aws_iam_access_key", "user", adaptAccessKey,
		); ok {
			user.AccessKeys = append(user.AccessKeys, accessKey)
		}

		users = append(users, user)
	}
	return users

}

func adaptAccessKey(block *terraform.Block) iam.AccessKey {

	active := iacTypes.BoolDefault(true, block.GetMetadata())
	if activeAttr := block.GetAttribute("status"); activeAttr.IsString() {
		active = iacTypes.Bool(activeAttr.Equals("Active"), activeAttr.GetMetadata())
	}
	return iam.AccessKey{
		Metadata:     block.GetMetadata(),
		AccessKeyId:  iacTypes.StringUnresolvable(block.GetMetadata()),
		CreationDate: iacTypes.TimeUnresolvable(block.GetMetadata()),
		LastAccess:   iacTypes.TimeUnresolvable(block.GetMetadata()),
		Active:       active,
	}
}
