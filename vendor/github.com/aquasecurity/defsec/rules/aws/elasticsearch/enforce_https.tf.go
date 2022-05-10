package elasticsearch

var terraformEnforceHttpsGoodExamples = []string{
	`
 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
   }
 }
 `,
}

var terraformEnforceHttpsBadExamples = []string{
	`
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = false
   }
 }
 `,
}

var terraformEnforceHttpsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https`,
}

var terraformEnforceHttpsRemediationMarkdown = ``
