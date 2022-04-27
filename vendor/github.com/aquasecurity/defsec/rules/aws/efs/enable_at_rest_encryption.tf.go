package efs

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "aws_efs_file_system" "good_example" {
   name       = "bar"
   encrypted  = true
   kms_key_id = "my_kms_key"
 }`,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
 resource "aws_efs_file_system" "bad_example" {
   name       = "bar"
   encrypted  = false
   kms_key_id = ""
 }`,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
