package vpc

var terraformAddDescriptionToSecurityGroupGoodExamples = []string{
	`
 resource "aws_security_group" "good_example" {
   name        = "http"
   description = "Allow inbound HTTP traffic"
 
   ingress {
     description = "HTTP from VPC"
     from_port   = 80
     to_port     = 80
     protocol    = "tcp"
     cidr_blocks = [aws_vpc.main.cidr_block]
   }
 }
 `,
}

var terraformAddDescriptionToSecurityGroupBadExamples = []string{
	`
 resource "aws_security_group" "bad_example" {
   name        = "http"
   description = ""
 
   ingress {
     description = "HTTP from VPC"
     from_port   = 80
     to_port     = 80
     protocol    = "tcp"
     cidr_blocks = [aws_vpc.main.cidr_block]
   }
 }
 `,
}

var terraformAddDescriptionToSecurityGroupLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group`, `https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule`,
}

var terraformAddDescriptionToSecurityGroupRemediationMarkdown = ``
