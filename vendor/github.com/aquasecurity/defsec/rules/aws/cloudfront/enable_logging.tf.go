package cloudfront

var terraformEnableLoggingGoodExamples = []string{
	`
 resource "aws_cloudfront_distribution" "good_example" {
 	// other config
 	logging_config {
 		include_cookies = false
 		bucket          = "mylogs.s3.amazonaws.com"
 		prefix          = "myprefix"
 	}
 }
 `,
}

var terraformEnableLoggingBadExamples = []string{
	`
 resource "aws_cloudfront_distribution" "bad_example" {
 	// other config
 	// no logging_config
 }
 `,
}

var terraformEnableLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config`,
}

var terraformEnableLoggingRemediationMarkdown = ``
