package cloudtrail

var terraformEnableAllRegionsGoodExamples = []string{
	`
 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 `,
}

var terraformEnableAllRegionsBadExamples = []string{
	`
 resource "aws_cloudtrail" "bad_example" {
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 `,
}

var terraformEnableAllRegionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail`,
}

var terraformEnableAllRegionsRemediationMarkdown = ``
