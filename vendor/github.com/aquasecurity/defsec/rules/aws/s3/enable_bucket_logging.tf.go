package s3

var terraformEnableBucketLoggingGoodExamples = []string{
	`
resource "aws_s3_bucket" "good_example" {
	logging {
		target_bucket = "target-bucket"
	}
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
