package s3

var terraformNoPublicAccessWithAclGoodExamples = []string{
	`
resource "aws_s3_bucket" "good_example" {
	acl = "private"
}
`, `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}`,
}

var terraformNoPublicAccessWithAclBadExamples = []string{
	`
resource "aws_s3_bucket" "bad_example" {
	acl = "public-read"
}
`, `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "authenticated-read"
}`,
}

var terraformNoPublicAccessWithAclLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket`,
}

var terraformNoPublicAccessWithAclRemediationMarkdown = ``
