package iam

var terraformRequireSymbolsInPasswordsGoodExamples = []string{
	`
 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	require_symbols = true
 	# ...
 }
 `,
}

var terraformRequireSymbolsInPasswordsBadExamples = []string{
	`
 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	# require_symbols not set
 	# ...
 }
 `,
}

var terraformRequireSymbolsInPasswordsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy`,
}

var terraformRequireSymbolsInPasswordsRemediationMarkdown = ``
