package autoscaling

var terraformNoPublicIpGoodExamples = []string{
	`
 resource "aws_launch_configuration" "good_example" {
 	associate_public_ip_address = false
 }
 `,
}

var terraformNoPublicIpBadExamples = []string{
	`
 resource "aws_launch_configuration" "bad_example" {
 	associate_public_ip_address = true
 }
 `,
}

var terraformNoPublicIpLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#associate_public_ip_address`, `https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address`,
}

var terraformNoPublicIpRemediationMarkdown = ``
