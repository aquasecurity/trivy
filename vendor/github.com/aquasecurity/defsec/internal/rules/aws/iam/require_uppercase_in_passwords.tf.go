package iam

var terraformRequireUppercaseInPasswordsGoodExamples = []string{
	`
 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	require_uppercase_characters = true
 	# ...
 }
 `,
}

var terraformRequireUppercaseInPasswordsBadExamples = []string{
	`
 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	# require_uppercase_characters not set
 	# ...
 }
 `,
}

var terraformRequireUppercaseInPasswordsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy`,
}

var terraformRequireUppercaseInPasswordsRemediationMarkdown = ``
