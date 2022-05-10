package ec2

var terraformNoSecretsInUserDataGoodExamples = []string{
	`
 resource "aws_iam_instance_profile" "good_example" {
		 // ...
 }
 
 resource "aws_instance" "good_example" {
	 ami           = "ami-12345667"
	 instance_type = "t2.small"
 
	 iam_instance_profile = aws_iam_instance_profile.good_profile.arn
 
	 user_data = <<EOF
	 export GREETING=hello
 EOF
 }
 `,
}

var terraformNoSecretsInUserDataBadExamples = []string{
	`
 resource "aws_instance" "bad_example" {
 
	 ami           = "ami-12345667"
	 instance_type = "t2.small"
 
	 user_data = <<EOF
 export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
 export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
 export AWS_DEFAULT_REGION=us-west-2 
 EOF
 }
 `,
}

var terraformNoSecretsInUserDataLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data`,
}

var terraformNoSecretsInUserDataRemediationMarkdown = ``
