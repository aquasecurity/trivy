package autoscaling

var terraformEnforceHttpTokenImdsGoodExamples = []string{
	`
 resource "aws_launch_template" "good_example" {
	 image_id      = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
	 metadata_options {
	   http_tokens = "required"
	 }	
 }
 `,
}

var terraformEnforceHttpTokenImdsBadExamples = []string{
	`
 resource "aws_launch_template" "bad_example" {
	 image_id      = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
 }
 `,
}

var terraformEnforceHttpTokenImdsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options`,
}

var terraformEnforceHttpTokenImdsRemediationMarkdown = ``
