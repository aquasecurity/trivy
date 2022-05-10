package vpc

var terraformNoPublicEgressSgrGoodExamples = []string{
	`
 resource "aws_security_group" "good_example" {
 	egress {
 		cidr_blocks = ["1.2.3.4/32"]
 	}
 }
 `,
}

var terraformNoPublicEgressSgrBadExamples = []string{
	`
 resource "aws_security_group" "bad_example" {
 	egress {
 		cidr_blocks = ["0.0.0.0/0"]
 	}
 }
 `,
}

var terraformNoPublicEgressSgrLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group`,
}

var terraformNoPublicEgressSgrRemediationMarkdown = ``
