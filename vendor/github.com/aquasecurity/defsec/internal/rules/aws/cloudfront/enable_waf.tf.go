package cloudfront

var terraformEnableWafGoodExamples = []string{
	`
 resource "aws_cloudfront_distribution" "good_example" {
 
   origin {
     domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
     origin_id   = "primaryS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.failover.bucket_regional_domain_name
     origin_id   = "failoverS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   default_cache_behavior {
     target_origin_id = "groupS3"
   }
 
   web_acl_id = "waf_id"
 }
 `,
}

var terraformEnableWafBadExamples = []string{
	`
 resource "aws_cloudfront_distribution" "bad_example" {
   origin_group {
     origin_id = "groupS3"
 
     failover_criteria {
       status_codes = [403, 404, 500, 502]
     }
 
     member {
       origin_id = "primaryS3"
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
     origin_id   = "primaryS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.failover.bucket_regional_domain_name
     origin_id   = "failoverS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   default_cache_behavior {
     target_origin_id = "groupS3"
   }
 }
 `,
}

var terraformEnableWafLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#web_acl_id`,
}

var terraformEnableWafRemediationMarkdown = ``
