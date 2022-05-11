package iam

var terraformRequireNumbersInPasswordsGoodExamples = []string{
	`
 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	require_numbers = true
 	# ...
 }
 `,
}

var terraformRequireNumbersInPasswordsBadExamples = []string{
	`
 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	# require_numbers not set
 	# ...
 }
 `,
}

var terraformRequireNumbersInPasswordsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy`,
}

var terraformRequireNumbersInPasswordsRemediationMarkdown = ``
