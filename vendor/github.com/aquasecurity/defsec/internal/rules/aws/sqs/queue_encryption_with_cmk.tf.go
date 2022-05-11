package sqs

var terraformQueueEncryptionUsesCMKGoodExamples = []string{
	`
 resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
 `,
}

var terraformQueueEncryptionUsesCMKBadExamples = []string{
	`
 resource "aws_sqs_queue" "bad_example" {
	kms_master_key_id = "alias/aws/sqs"
 }
 `,
}

var terraformQueueEncryptionUsesCMKLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse`,
}

var terraformQueueEncryptionUsesCMKRemediationMarkdown = ``
