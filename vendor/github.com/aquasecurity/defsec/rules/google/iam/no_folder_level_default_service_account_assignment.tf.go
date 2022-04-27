package iam

var terraformNoFolderLevelDefaultServiceAccountAssignmentGoodExamples = []string{
	`
 resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
 }
 			  
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 `,
}

var terraformNoFolderLevelDefaultServiceAccountAssignmentBadExamples = []string{
	`
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = "123-compute@developer.gserviceaccount.com"
 }
 `, `
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = "123@appspot.gserviceaccount.com"
 }
 `, `
 data "google_compute_default_service_account" "default" {
 }
 
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = data.google_compute_default_service_account.default.id
 }
 `,
}

var terraformNoFolderLevelDefaultServiceAccountAssignmentLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam`, ``,
}

var terraformNoFolderLevelDefaultServiceAccountAssignmentRemediationMarkdown = ``
