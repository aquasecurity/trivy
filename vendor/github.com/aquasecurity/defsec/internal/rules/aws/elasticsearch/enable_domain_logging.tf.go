package elasticsearch

var terraformEnableDomainLoggingGoodExamples = []string{
	`
 resource "aws_elasticsearch_domain" "good_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "AUDIT_LOGS"
     enabled                  = true  
   }
 }
 `,
}

var terraformEnableDomainLoggingBadExamples = []string{
	`
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 }
 `, `
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "AUDIT_LOGS"
     enabled                  = false  
   }
 }
 `,
}

var terraformEnableDomainLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type`,
}

var terraformEnableDomainLoggingRemediationMarkdown = ``
