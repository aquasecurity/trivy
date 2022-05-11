package iam

var terraformSetMaxPasswordAgeGoodExamples = []string{
	`
resource "aws_iam_account_password_policy" "good_example" {
	max_password_age = 90
}`,
}

var terraformSetMaxPasswordAgeBadExamples = []string{
	`
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# max_password_age not set
	# ...
}`,
}

var terraformSetMaxPasswordAgeLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy`,
}

var terraformSetMaxPasswordAgeRemediationMarkdown = ``
