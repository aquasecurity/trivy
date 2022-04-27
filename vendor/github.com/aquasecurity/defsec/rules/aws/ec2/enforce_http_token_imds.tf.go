package ec2

var terraformEnforceHttpTokenImdsGoodExamples = []string{
	`
 resource "aws_instance" "good_example" {
	 ami           = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
	 metadata_options {
	 http_tokens = "required"
	 }	
 }
 `,
}

var terraformEnforceHttpTokenImdsBadExamples = []string{
	`
 resource "aws_instance" "bad_example" {
	 ami           = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
 }
 `,
}

var terraformEnforceHttpTokenImdsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options`,
}

var terraformEnforceHttpTokenImdsRemediationMarkdown = ``
