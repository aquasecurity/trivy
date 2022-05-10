package storage

var terraformNoPublicAccessGoodExamples = []string{
	`
 resource "azurerm_storage_container" "good_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "private"
 }
 `,
}

var terraformNoPublicAccessBadExamples = []string{
	`
 resource "azurerm_storage_container" "bad_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "blob"
 	
 	properties = {
 		"publicAccess" = "blob"
 	}
 }
 `,
}

var terraformNoPublicAccessLinks = []string{
	`https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties`,
}

var terraformNoPublicAccessRemediationMarkdown = ``
