package s3

var terraformNoPublicAccessWithAclGoodExamples = []string{
	`
resource "aws_s3_bucket" "good_example" {
	acl = "private"
}
`,
}

var terraformNoPublicAccessWithAclBadExamples = []string{
	`
resource "aws_s3_bucket" "bad_example" {
	acl = "public-read"
}
`,
}

var terraformNoPublicAccessWithAclLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket`,
}

var terraformNoPublicAccessWithAclRemediationMarkdown = ``
