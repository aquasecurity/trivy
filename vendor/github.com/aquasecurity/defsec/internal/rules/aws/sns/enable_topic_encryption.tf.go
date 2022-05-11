package sns

var terraformEnableTopicEncryptionGoodExamples = []string{
	`
 resource "aws_sns_topic" "good_example" {
 	kms_master_key_id = "/blah"
 }
 `,
}

var terraformEnableTopicEncryptionBadExamples = []string{
	`
 resource "aws_sns_topic" "bad_example" {
 	# no key id specified
 }
 `,
}

var terraformEnableTopicEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse`,
}

var terraformEnableTopicEncryptionRemediationMarkdown = ``
