package documentdb

var terraformEncryptionCustomerKeyGoodExamples = []string{
	`
 resource "aws_kms_key" "docdb_encryption" {
 	enable_key_rotation = true
 }
 			
 resource "aws_docdb_cluster" "docdb" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   kms_key_id 			  = aws_kms_key.docdb_encryption.arn
 }
 `,
}

var terraformEncryptionCustomerKeyBadExamples = []string{
	`
 resource "aws_docdb_cluster" "docdb" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
 }
 `,
}

var terraformEncryptionCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#kms_key_id`,
}

var terraformEncryptionCustomerKeyRemediationMarkdown = ``
