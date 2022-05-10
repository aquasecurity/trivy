package elasticache

var terraformEnableInTransitEncryptionGoodExamples = []string{
	`
 resource "aws_elasticache_replication_group" "good_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
         transit_encryption_enabled = true
 }
 `,
}

var terraformEnableInTransitEncryptionBadExamples = []string{
	`
 resource "aws_elasticache_replication_group" "bad_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
         transit_encryption_enabled = false
 }
 `,
}

var terraformEnableInTransitEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled`,
}

var terraformEnableInTransitEncryptionRemediationMarkdown = ``
