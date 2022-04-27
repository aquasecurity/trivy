package iam

var terraformNoProjectLevelDefaultServiceAccountAssignmentGoodExamples = []string{
	`
 resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
 }
 			  
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 `,
}

var terraformNoProjectLevelDefaultServiceAccountAssignmentBadExamples = []string{
	`
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = "123-compute@developer.gserviceaccount.com"
 }
 `, `
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = "123@appspot.gserviceaccount.com"
 }
 `, `
 data "google_compute_default_service_account" "default" {
 }
 
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = data.google_compute_default_service_account.default.id
 }
 `,
}

var terraformNoProjectLevelDefaultServiceAccountAssignmentLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam`, ``,
}

var terraformNoProjectLevelDefaultServiceAccountAssignmentRemediationMarkdown = ``
