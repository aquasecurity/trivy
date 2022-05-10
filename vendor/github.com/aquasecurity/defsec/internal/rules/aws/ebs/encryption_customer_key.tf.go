package ebs

var terraformEncryptionCustomerKeyGoodExamples = []string{
	`
 resource "aws_kms_key" "ebs_encryption" {
 	enable_key_rotation = true
 }
 
 resource "aws_ebs_volume" "example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   kms_key_id = aws_kms_key.ebs_encryption.arn
 
   tags = {
     Name = "HelloWorld"
   }
 }
 `,
}

var terraformEncryptionCustomerKeyBadExamples = []string{
	`
 resource "aws_ebs_volume" "example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   tags = {
     Name = "HelloWorld"
   }
 }
 `,
}

var terraformEncryptionCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#kms_key_id`,
}

var terraformEncryptionCustomerKeyRemediationMarkdown = ``
