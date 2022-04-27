package iam

var terraformNoPrivilegedServiceAccountsGoodExamples = []string{
	`
 resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
    email        = "jim@tfsec.dev"
 }
 
 resource "google_project_iam_member" "project" {
 	project = "your-project-id"
 	role    = "roles/logging.logWriter"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 			`,
}

var terraformNoPrivilegedServiceAccountsBadExamples = []string{
	`
 resource "google_service_account" "test" {
   account_id   = "account123"
   display_name = "account123"
   email        = "jim@tfsec.dev"
 }
 
 resource "google_project_iam_member" "project" {
 	project = "your-project-id"
 	role    = "roles/owner"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 			`,
}

var terraformNoPrivilegedServiceAccountsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam`,
}

var terraformNoPrivilegedServiceAccountsRemediationMarkdown = ``
