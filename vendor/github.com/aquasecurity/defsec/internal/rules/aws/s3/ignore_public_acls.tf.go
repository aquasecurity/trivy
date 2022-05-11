package s3

var terraformIgnorePublicAclsGoodExamples = []string{
	`
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

 resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	ignore_public_acls = true
 }
 `,
}

var terraformIgnorePublicAclsBadExamples = []string{
	`
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}


 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
 }
 
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
   
 	ignore_public_acls = false
 }
 `,
}

var terraformIgnorePublicAclsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#ignore_public_acls`,
}

var terraformIgnorePublicAclsRemediationMarkdown = ``
