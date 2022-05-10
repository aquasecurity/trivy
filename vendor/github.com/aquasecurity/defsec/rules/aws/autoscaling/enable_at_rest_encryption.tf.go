package autoscaling

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "aws_launch_configuration" "good_example" {
 	root_block_device {
 		encrypted = true
 	}
 }
 `,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
 resource "aws_launch_configuration" "bad_example" {
 	root_block_device {
 		encrypted = false
 	}
 }
 `,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
