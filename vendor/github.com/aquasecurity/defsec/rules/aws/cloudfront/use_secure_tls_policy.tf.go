package cloudfront

var terraformUseSecureTlsPolicyGoodExamples = []string{
	`
 resource "aws_cloudfront_distribution" "good_example" {
   viewer_certificate {
     cloudfront_default_certificate = true
     minimum_protocol_version = "TLSv1.2_2021"
   }
 }
 `,
}

var terraformUseSecureTlsPolicyBadExamples = []string{
	`
 resource "aws_cloudfront_distribution" "bad_example" {
   viewer_certificate {
     cloudfront_default_certificate = true
     minimum_protocol_version = "TLSv1.0"
   }
 }
 `,
}

var terraformUseSecureTlsPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#minimum_protocol_version`,
}

var terraformUseSecureTlsPolicyRemediationMarkdown = ``
