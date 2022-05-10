package vpc

var terraformNoPublicIngressSgrGoodExamples = []string{
	`
 resource "aws_security_group_rule" "good_example" {
 	type = "ingress"
 	cidr_blocks = ["10.0.0.0/16"]
 }
 `,
	`
resource "aws_security_group_rule" "allow_partner_rsync" {
  type              = "ingress"
  security_group_id = aws_security_group.….id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks = [
    "1.2.3.4/32",
    "4.5.6.7/32",
  ]
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
