package vpc

var terraformNoPublicIngressSgrGoodExamples = []string{
	`
 resource "aws_security_group_rule" "good_example" {
 	type = "ingress"
 	cidr_blocks = ["10.0.0.0/16"]
 }
 `,
}

var terraformNoPublicIngressSgrBadExamples = []string{
	`
 resource "aws_security_group_rule" "bad_example" {
 	type = "ingress"
 	cidr_blocks = ["0.0.0.0/0"]
 }
 `,
}

var terraformNoPublicIngressSgrLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule#cidr_blocks`,
}

var terraformNoPublicIngressSgrRemediationMarkdown = ``
