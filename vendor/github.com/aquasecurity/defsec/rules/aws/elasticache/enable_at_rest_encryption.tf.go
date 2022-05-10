package elasticache

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "aws_elasticache_replication_group" "good_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
 
         at_rest_encryption_enabled = true
 }
 `,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
 resource "aws_elasticache_replication_group" "bad_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
 
         at_rest_encryption_enabled = false
 }
 `,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
