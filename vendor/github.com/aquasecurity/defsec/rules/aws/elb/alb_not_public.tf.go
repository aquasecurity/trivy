package elb

var terraformAlbNotPublicGoodExamples = []string{
	`
 resource "aws_alb" "good_example" {
 	internal = true
 }
 `,
}

var terraformAlbNotPublicBadExamples = []string{
	`
 resource "aws_alb" "bad_example" {
 	internal = false
 }
 `,
}

var terraformAlbNotPublicLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb`,
}

var terraformAlbNotPublicRemediationMarkdown = ``
