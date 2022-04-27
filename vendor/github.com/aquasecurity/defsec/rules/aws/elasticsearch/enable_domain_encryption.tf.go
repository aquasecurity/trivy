package elasticsearch

var terraformEnableDomainEncryptionGoodExamples = []string{
	`
 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   encrypt_at_rest {
     enabled = true
   }
 }
 `,
}

var terraformEnableDomainEncryptionBadExamples = []string{
	`
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name = "domain-foo"
 
   encrypt_at_rest {
     enabled = false
   }
 }
 `,
}

var terraformEnableDomainEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest`,
}

var terraformEnableDomainEncryptionRemediationMarkdown = ``
