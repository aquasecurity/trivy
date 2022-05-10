package rds

var terraformNoPublicDbAccessGoodExamples = []string{
	`
 resource "aws_db_instance" "good_example" {
 	publicly_accessible = false
 }
 `,
}

var terraformNoPublicDbAccessBadExamples = []string{
	`
 resource "aws_db_instance" "bad_example" {
 	publicly_accessible = true
 }
 `,
}

var terraformNoPublicDbAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance`,
}

var terraformNoPublicDbAccessRemediationMarkdown = ``
