package keyvault

var terraformEnsureSecretExpiryGoodExamples = []string{
	`
 resource "azurerm_key_vault_secret" "good_example" {
   name            = "secret-sauce"
   value           = "szechuan"
   key_vault_id    = azurerm_key_vault.example.id
   expiration_date = "1982-12-31T00:00:00Z"
 }
 `,
}

var terraformEnsureSecretExpiryBadExamples = []string{
	`
 resource "azurerm_key_vault_secret" "bad_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
 }
 `,
}

var terraformEnsureSecretExpiryLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date`,
}

var terraformEnsureSecretExpiryRemediationMarkdown = ``
