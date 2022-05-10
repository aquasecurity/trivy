package rds

var terraformEnablePerformanceInsightsGoodExamples = []string{
	`
resource "aws_rds_cluster_instance" "good_example" {
	name = "bar"
	performance_insights_enabled = true
	performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
		`,
}

var terraformEnablePerformanceInsightsBadExamples = []string{
	`
resource "aws_rds_cluster_instance" "bad_example" {
	name = "bar"
	performance_insights_enabled = true
	performance_insights_kms_key_id = ""
}
		`,
}

var terraformEnablePerformanceInsightsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id`, `https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id`,
}

var terraformEnablePerformanceInsightsRemediationMarkdown = ``
