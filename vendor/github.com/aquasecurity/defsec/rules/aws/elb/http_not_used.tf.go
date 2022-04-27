package elb

var terraformHttpNotUsedGoodExamples = []string{
	`
 resource "aws_alb_listener" "good_example" {
 	protocol = "HTTPS"
 }
 `,
}

var terraformHttpNotUsedBadExamples = []string{
	`
 resource "aws_alb_listener" "bad_example" {
 	protocol = "HTTP"
 }
 `,
}

var terraformHttpNotUsedLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener`,
}

var terraformHttpNotUsedRemediationMarkdown = ``
