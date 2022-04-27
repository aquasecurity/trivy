package iam

var terraformNoOrgLevelDefaultServiceAccountAssignmentGoodExamples = []string{
	`
 resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
 }
 			  
 resource "google_organization_iam_member" "org-123" {
 	org_id = "org-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 `,
}

var terraformNoOrgLevelDefaultServiceAccountAssignmentBadExamples = []string{
	`
 resource "google_organization_iam_member" "org-123" {
 	org_id = "organization-123"
 	role    = "roles/whatever"
 	member  = "123-compute@developer.gserviceaccount.com"
 }
 `, `
 resource "google_organization_iam_member" "org-123" {
 	org_id = "org-123"
 	role    = "roles/whatever"
 	member  = "123@appspot.gserviceaccount.com"
 }
 `, `
 data "google_compute_default_service_account" "default" {
 }
 
 resource "google_organization_iam_member" "org-123" {
 	org_id = "org-123"
 	role    = "roles/whatever"
 	member  = data.google_compute_default_service_account.default.id
 }
 `,
}

var terraformNoOrgLevelDefaultServiceAccountAssignmentLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam`, ``,
}

var terraformNoOrgLevelDefaultServiceAccountAssignmentRemediationMarkdown = ``
