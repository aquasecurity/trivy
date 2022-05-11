package s3

var terraformBlockPublicAclsGoodExamples = []string{
	`
resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
  bucket = aws_s3_bucket.good_example.id
  block_public_acls = true
}
 `,
}

var terraformBlockPublicAclsBadExamples = []string{
	`
resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.bad_example.id
}
 `, `
resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.bad_example.id
  block_public_acls = false
}
 `,
}

var terraformBlockPublicAclsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls`,
}

var terraformBlockPublicAclsRemediationMarkdown = ``
