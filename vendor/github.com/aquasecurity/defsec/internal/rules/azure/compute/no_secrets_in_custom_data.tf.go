package compute

var terraformNoSecretsInCustomDataGoodExamples = []string{
	`
 resource "azurerm_virtual_machine" "good_example" {
 	name = "good_example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
			export GREETING="Hello there"
			EOF
	}
 }
 `,
}

var terraformNoSecretsInCustomDataBadExamples = []string{
	`
 resource "azurerm_virtual_machine" "bad_example" {
 	name = "bad_example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
			export DATABASE_PASSWORD=\"SomeSortOfPassword\"
			EOF
	}
 }
 `,
}

var terraformNoSecretsInCustomDataLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#custom_data`,
}

var terraformNoSecretsInCustomDataRemediationMarkdown = ``
