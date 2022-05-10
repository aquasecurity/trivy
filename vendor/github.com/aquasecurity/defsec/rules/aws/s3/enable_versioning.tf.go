package s3

var terraformEnableVersioningGoodExamples = []string{
	`
resource "aws_s3_bucket" "good_example" {

	versioning {
		enabled = true
	}
}
`,
}

var terraformEnableVersioningBadExamples = []string{
	`
resource "aws_s3_bucket" "bad_example" {

}
`,
}

var terraformEnableVersioningLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning`,
}

var terraformEnableVersioningRemediationMarkdown = ``
