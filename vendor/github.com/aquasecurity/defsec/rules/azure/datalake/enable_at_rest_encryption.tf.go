package datalake

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "azurerm_data_lake_store" "good_example" {
 	encryption_state = "Enabled"
 }`,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
 resource "azurerm_data_lake_store" "bad_example" {
 	encryption_state = "Disabled"
 }`,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_lake_store`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
