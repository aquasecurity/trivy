package iam

var terraformNoPasswordReuseGoodExamples = []string{
	`
 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	password_reuse_prevention = 5
 	# ...
 }
 			`,
}

var terraformNoPasswordReuseBadExamples = []string{
	`
 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	password_reuse_prevention = 1
 	# ...
 }
 			`,
}

var terraformNoPasswordReuseLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy`,
}

var terraformNoPasswordReuseRemediationMarkdown = ``
