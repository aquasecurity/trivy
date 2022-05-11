package iam

var terraformSetMinimumPasswordLengthGoodExamples = []string{
	`
resource "aws_iam_account_password_policy" "good_example" {
	minimum_password_length = 14
}
	`,
}

var terraformSetMinimumPasswordLengthBadExamples = []string{
	`
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# minimum_password_length not set
	# ...
}
		`,
}

var terraformSetMinimumPasswordLengthLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy`,
}

var terraformSetMinimumPasswordLengthRemediationMarkdown = ``
