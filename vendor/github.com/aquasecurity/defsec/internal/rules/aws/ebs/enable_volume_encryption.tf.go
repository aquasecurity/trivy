package ebs

var terraformEnableVolumeEncryptionGoodExamples = []string{
	`
 resource "aws_ebs_volume" "good_example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   tags = {
     Name = "HelloWorld"
   }
   encrypted = true
 }
 `,
}

var terraformEnableVolumeEncryptionBadExamples = []string{
	`
 resource "aws_ebs_volume" "bad_example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   tags = {
     Name = "HelloWorld"
   }
   encrypted = false
 }
 `,
}

var terraformEnableVolumeEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted`,
}

var terraformEnableVolumeEncryptionRemediationMarkdown = ``
