package keyvault

var terraformContentTypeForSecretGoodExamples = []string{
	`
 resource "azurerm_key_vault_secret" "good_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
   content_type = "password"
 }
 `,
}

var terraformContentTypeForSecretBadExamples = []string{
	`
 resource "azurerm_key_vault_secret" "bad_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
 }
 `,
}

var terraformContentTypeForSecretLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#content_type`,
}

var terraformContentTypeForSecretRemediationMarkdown = ``
