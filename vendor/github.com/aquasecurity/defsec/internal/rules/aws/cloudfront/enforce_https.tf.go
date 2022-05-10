package cloudfront

var terraformEnforceHttpsGoodExamples = []string{
	`
 resource "aws_cloudfront_distribution" "good_example" {
 	default_cache_behavior {
 	    viewer_protocol_policy = "redirect-to-https"
 	  }
 }
 `,
}

var terraformEnforceHttpsBadExamples = []string{
	`
 resource "aws_cloudfront_distribution" "bad_example" {
 	default_cache_behavior {
 	    viewer_protocol_policy = "allow-all"
 	  }
 }
 `,
}

var terraformEnforceHttpsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy`,
}

var terraformEnforceHttpsRemediationMarkdown = ``
