package config

var terraformAggregateAllRegionsGoodExamples = []string{
	`
 resource "aws_config_configuration_aggregator" "good_example" {
 	name = "example"
 	  
 	account_aggregation_source {
 	  account_ids = ["123456789012"]
 	  all_regions = true
 	}
 }
 `,
}

var terraformAggregateAllRegionsBadExamples = []string{
	`
 resource "aws_config_configuration_aggregator" "bad_example" {
 	name = "example"
 	  
 	account_aggregation_source {
 	  account_ids = ["123456789012"]
 	  regions     = ["us-west-2", "eu-west-1"]
 	}
 }
 `,
}

var terraformAggregateAllRegionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions`,
}

var terraformAggregateAllRegionsRemediationMarkdown = ``
