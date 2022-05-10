package documentdb

var terraformEnableLogExportGoodExamples = []string{
	`
 resource "aws_docdb_cluster" "good_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   enabled_cloudwatch_logs_exports = "audit"
 }
 `,
}

var terraformEnableLogExportBadExamples = []string{
	`
 resource "aws_docdb_cluster" "bad_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   enabled_cloudwatch_logs_exports = "something"
 }
 `,
}

var terraformEnableLogExportLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#enabled_cloudwatch_logs_exports`,
}

var terraformEnableLogExportRemediationMarkdown = ``
