package s3

var terraformEnableBucketLoggingGoodExamples = []string{
	`
resource "aws_s3_bucket" "good_example" {
	logging {
		target_bucket = "target-bucket"
	}
}
`, `

resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}
`,
}

var terraformEnableBucketLoggingBadExamples = []string{
	`
resource "aws_s3_bucket" "bad_example" {

}
`,
}

var terraformEnableBucketLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket`,
}

var terraformEnableBucketLoggingRemediationMarkdown = ``
