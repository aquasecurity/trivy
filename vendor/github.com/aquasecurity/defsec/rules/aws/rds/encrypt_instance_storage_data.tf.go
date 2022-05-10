package rds

var terraformEncryptInstanceStorageDataGoodExamples = []string{
	`
 resource "aws_db_instance" "good_example" {
 	storage_encrypted  = true
 }
 `,
}

var terraformEncryptInstanceStorageDataBadExamples = []string{
	`
 resource "aws_db_instance" "bad_example" {
 	
 }
 `,
}

var terraformEncryptInstanceStorageDataLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance`,
}

var terraformEncryptInstanceStorageDataRemediationMarkdown = ``
