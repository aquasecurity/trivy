package rds

var terraformNoClassicResourcesGoodExamples = []string{
	`
 resource "aws_security_group" "good_example" {
   # ...
 }
 `,
}

var terraformNoClassicResourcesBadExamples = []string{
	`
 resource "aws_db_security_group" "bad_example" {
   # ...
 }
 `,
}

var terraformNoClassicResourcesLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_security_group`,
}

var terraformNoClassicResourcesRemediationMarkdown = ``
