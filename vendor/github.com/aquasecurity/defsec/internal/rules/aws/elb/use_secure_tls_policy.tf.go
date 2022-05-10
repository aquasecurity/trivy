package elb

var terraformUseSecureTlsPolicyGoodExamples = []string{
	`
 resource "aws_alb_listener" "good_example" {
 	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
 	protocol = "HTTPS"
 }
 `,
}

var terraformUseSecureTlsPolicyBadExamples = []string{
	`
 resource "aws_alb_listener" "bad_example" {
 	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
 	protocol = "HTTPS"
 }
 `,
}

var terraformUseSecureTlsPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener`,
}

var terraformUseSecureTlsPolicyRemediationMarkdown = ``
