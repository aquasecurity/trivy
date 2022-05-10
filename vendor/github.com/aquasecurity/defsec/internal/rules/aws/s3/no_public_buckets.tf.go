package s3

var terraformNoPublicBucketsGoodExamples = []string{
	`
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	restrict_public_buckets = true
 }
 `,
}

var terraformNoPublicBucketsBadExamples = []string{
	`
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
 }
 
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
   
 	restrict_public_buckets = false
 }
 `,
}

var terraformNoPublicBucketsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡`,
}

var terraformNoPublicBucketsRemediationMarkdown = ``
