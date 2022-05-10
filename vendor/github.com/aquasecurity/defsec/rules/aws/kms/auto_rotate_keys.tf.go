package kms

var terraformAutoRotateKeysGoodExamples = []string{
	`
 resource "aws_kms_key" "good_example" {
 	enable_key_rotation = true
 }
 `,
}

var terraformAutoRotateKeysBadExamples = []string{
	`
 resource "aws_kms_key" "bad_example" {
 	enable_key_rotation = false
 }
 `,
}

var terraformAutoRotateKeysLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation`,
}

var terraformAutoRotateKeysRemediationMarkdown = ``
