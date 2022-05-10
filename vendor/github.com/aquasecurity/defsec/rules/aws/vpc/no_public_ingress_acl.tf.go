package vpc

var terraformNoPublicIngressAclGoodExamples = []string{
	`
 resource "aws_network_acl_rule" "good_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "10.0.0.0/16"
 }
 `,
}

var terraformNoPublicIngressAclBadExamples = []string{
	`
 resource "aws_network_acl_rule" "bad_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 `,
}

var terraformNoPublicIngressAclLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#cidr_block`,
}

var terraformNoPublicIngressAclRemediationMarkdown = ``
