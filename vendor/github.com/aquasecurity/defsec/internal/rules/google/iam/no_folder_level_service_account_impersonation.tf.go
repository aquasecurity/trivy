package iam

var terraformNoFolderLevelServiceAccountImpersonationGoodExamples = []string{
	`
 resource "google_folder_iam_binding" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/nothingInParticular"
 }
 			`,
}

var terraformNoFolderLevelServiceAccountImpersonationBadExamples = []string{
	`
 resource "google_folder_iam_binding" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/iam.serviceAccountUser"
 }
 `, `
 resource "google_folder_iam_binding" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/iam.serviceAccountTokenCreator"
 }
 `,
}

var terraformNoFolderLevelServiceAccountImpersonationLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam`,
}

var terraformNoFolderLevelServiceAccountImpersonationRemediationMarkdown = ``
