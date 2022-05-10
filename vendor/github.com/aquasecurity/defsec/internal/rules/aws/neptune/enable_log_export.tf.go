package neptune

var terraformEnableLogExportGoodExamples = []string{
	`
 resource "aws_neptune_cluster" "good_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   enable_cloudwatch_logs_exports      = ["audit"]
 }
 `,
}

var terraformEnableLogExportBadExamples = []string{
	`
 resource "aws_neptune_cluster" "bad_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   enable_cloudwatch_logs_exports      = []
 }
 `,
}

var terraformEnableLogExportLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#enable_cloudwatch_logs_exports`,
}

var terraformEnableLogExportRemediationMarkdown = ``
