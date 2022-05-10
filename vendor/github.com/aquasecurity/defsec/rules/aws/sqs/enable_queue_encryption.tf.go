package sqs

var terraformEnableQueueEncryptionGoodExamples = []string{
	`
 resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
 `,
}

var terraformEnableQueueEncryptionBadExamples = []string{
	`
 resource "aws_sqs_queue" "bad_example" {
 	# no key specified
 }
 `,
}

var terraformEnableQueueEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse`,
}

var terraformEnableQueueEncryptionRemediationMarkdown = ``
