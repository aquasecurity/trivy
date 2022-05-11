package sns

var terraformTopicEncryptionUsesCMKGoodExamples = []string{
	`
 resource "aws_sns_topic" "good_example" {
 	kms_master_key_id = "/blah"
 }
 `,
}

var terraformTopicEncryptionUsesCMKBadExamples = []string{
	`
 resource "aws_sns_topic" "bad_example" {
    kms_master_key_id = "alias/aws/sns"
 }
 `,
}

var terraformTopicEncryptionUsesCMKLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse`,
}

var terraformTopicEncryptionUsesCMKRemediationMarkdown = ``
