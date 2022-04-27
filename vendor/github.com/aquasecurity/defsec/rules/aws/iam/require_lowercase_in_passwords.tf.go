package iam

var terraformRequireLowercaseInPasswordsGoodExamples = []string{
	`
 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	require_lowercase_characters = true
 	# ...
 }`,
}

var terraformRequireLowercaseInPasswordsBadExamples = []string{
	`
 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	# require_lowercase_characters not set
 	# ...
 }`,
}

var terraformRequireLowercaseInPasswordsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy`,
}

var terraformRequireLowercaseInPasswordsRemediationMarkdown = ``
