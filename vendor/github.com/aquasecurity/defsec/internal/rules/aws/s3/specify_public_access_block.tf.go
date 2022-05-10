package s3

var terraformSpecifyPublicAccessBlockGoodExamples = []string{
	`
 resource "aws_s3_bucket" "example" {
 	bucket = "example"
 	acl = "private-read"
 }
   
 resource "aws_s3_bucket_public_access_block" "example" {
 	bucket = aws_s3_bucket.example.id
 	block_public_acls   = true
 	block_public_policy = true
 }
 `,
}

var terraformSpecifyPublicAccessBlockBadExamples = []string{
	`
 resource "aws_s3_bucket" "example" {
 	bucket = "example"
 	acl = "private-read"
 }
 `,
}

var terraformSpecifyPublicAccessBlockLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket`,
}

var terraformSpecifyPublicAccessBlockRemediationMarkdown = ``
