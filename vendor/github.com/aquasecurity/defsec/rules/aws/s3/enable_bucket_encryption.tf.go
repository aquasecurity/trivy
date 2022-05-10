package s3

var terraformEnableBucketEncryptionGoodExamples = []string{
	`
 resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket"
 
   server_side_encryption_configuration {
     rule {
       apply_server_side_encryption_by_default {
         kms_master_key_id = "arn"
         sse_algorithm     = "aws:kms"
       }
     }
   }
 }
 `,
}

var terraformEnableBucketEncryptionBadExamples = []string{
	`
 resource "aws_s3_bucket" "bad_example" {
   bucket = "mybucket"
 }
 `,
}

var terraformEnableBucketEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption`,
}

var terraformEnableBucketEncryptionRemediationMarkdown = ``
