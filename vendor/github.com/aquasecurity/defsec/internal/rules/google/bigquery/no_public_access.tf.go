package bigquery

var terraformNoPublicAccessGoodExamples = []string{
	`
 resource "google_bigquery_dataset" "good_example" {
   dataset_id                  = "example_dataset"
   friendly_name               = "test"
   description                 = "This is a test description"
   location                    = "EU"
   default_table_expiration_ms = 3600000
 
   labels = {
     env = "default"
   }
 
   access {
     role          = "OWNER"
     user_by_email = google_service_account.bqowner.email
   }
 
   access {
     role   = "READER"
     domain = "hashicorp.com"
   }
 }
 
 resource "google_service_account" "bqowner" {
   account_id = "bqowner"
 }
 `,
}

var terraformNoPublicAccessBadExamples = []string{
	`
 resource "google_bigquery_dataset" "bad_example" {
   dataset_id                  = "example_dataset"
   friendly_name               = "test"
   description                 = "This is a test description"
   location                    = "EU"
   default_table_expiration_ms = 3600000
 
   labels = {
     env = "default"
   }
 
   access {
     role          = "OWNER"
     special_group = "allAuthenticatedUsers"
   }
 
   access {
     role   = "READER"
     domain = "hashicorp.com"
   }
 }
 
 `,
}

var terraformNoPublicAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigquery_dataset#special_group`,
}

var terraformNoPublicAccessRemediationMarkdown = ``
