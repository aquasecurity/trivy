package elb

var terraformDropInvalidHeadersGoodExamples = []string{
	`
 resource "aws_alb" "good_example" {
 	name               = "good_alb"
 	internal           = false
 	load_balancer_type = "application"
 	
 	access_logs {
 	  bucket  = aws_s3_bucket.lb_logs.bucket
 	  prefix  = "test-lb"
 	  enabled = true
 	}
   
 	drop_invalid_header_fields = true
   }
 `,
}

var terraformDropInvalidHeadersBadExamples = []string{
	`
 resource "aws_alb" "bad_example" {
 	name               = "bad_alb"
 	internal           = false
 	load_balancer_type = "application"
 	
 	access_logs {
 	  bucket  = aws_s3_bucket.lb_logs.bucket
 	  prefix  = "test-lb"
 	  enabled = true
 	}
   
 	drop_invalid_header_fields = false
   }
 `,
}

var terraformDropInvalidHeadersLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields`,
}

var terraformDropInvalidHeadersRemediationMarkdown = ``
