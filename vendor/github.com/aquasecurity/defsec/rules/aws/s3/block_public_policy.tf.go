package s3

var terraformBlockPublicPolicyGoodExamples = []string{
	`
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
  bucket = aws_s3_bucket.example.id 
  block_public_policy = true 
}
 `,
}

var terraformBlockPublicPolicyBadExamples = []string{
	`
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.example.id
}
 
resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.example.id 
  block_public_policy = false
}
 `,
}

var terraformBlockPublicPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_policy`,
}

var terraformBlockPublicPolicyRemediationMarkdown = ``
