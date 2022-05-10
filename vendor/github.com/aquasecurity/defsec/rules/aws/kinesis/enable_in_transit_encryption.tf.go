package kinesis

var terraformEnableInTransitEncryptionGoodExamples = []string{
	`
 resource "aws_kinesis_stream" "good_example" {
 	encryption_type = "KMS"
 	kms_key_id = "my/special/key"
 }
 `,
}

var terraformEnableInTransitEncryptionBadExamples = []string{
	`
 resource "aws_kinesis_stream" "bad_example" {
 	encryption_type = "NONE"
 }
 `,
}

var terraformEnableInTransitEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_stream#encryption_type`,
}

var terraformEnableInTransitEncryptionRemediationMarkdown = ``
