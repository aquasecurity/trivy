package vpc

var terraformNoExcessivePortAccessGoodExamples = []string{
	`
 resource "aws_network_acl_rule" "good_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 `,
}

var terraformNoExcessivePortAccessBadExamples = []string{
	`
 resource "aws_network_acl_rule" "bad_example" {
   egress         = false
   protocol       = "all"
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 `,
}

var terraformNoExcessivePortAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#to_port`,
}

var terraformNoExcessivePortAccessRemediationMarkdown = ``
