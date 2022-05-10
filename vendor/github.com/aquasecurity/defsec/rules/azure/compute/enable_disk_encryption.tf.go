package compute

var terraformEnableDiskEncryptionGoodExamples = []string{
	`
 resource "azurerm_managed_disk" "good_example" {
 	encryption_settings {
 		enabled = true
 	}
 }`,
}

var terraformEnableDiskEncryptionBadExamples = []string{
	`
 resource "azurerm_managed_disk" "bad_example" {
 	encryption_settings {
 		enabled = false
 	}
 }`,
}

var terraformEnableDiskEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk`,
}

var terraformEnableDiskEncryptionRemediationMarkdown = ``
