package elasticsearch

var terraformEnableInTransitEncryptionGoodExamples = []string{
	`
 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   node_to_node_encryption {
     enabled = true
   }
 }
 `,
}

var terraformEnableInTransitEncryptionBadExamples = []string{
	`
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name = "domain-foo"
 
   node_to_node_encryption {
     enabled = false
   }
 }
 `,
}

var terraformEnableInTransitEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest`,
}

var terraformEnableInTransitEncryptionRemediationMarkdown = ``
