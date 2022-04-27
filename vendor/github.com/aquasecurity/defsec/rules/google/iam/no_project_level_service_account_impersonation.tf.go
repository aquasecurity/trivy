package iam

var terraformNoProjectLevelServiceAccountImpersonationGoodExamples = []string{
	`
 resource "google_project_iam_binding" "project-123" {
 	project = "project-123"
 	role    = "roles/nothingInParticular"
 }
 			`,
}

var terraformNoProjectLevelServiceAccountImpersonationBadExamples = []string{
	`
 resource "google_project_iam_binding" "project-123" {
 	project = "project-123"
 	role    = "roles/iam.serviceAccountUser"
 }
 `, `
 resource "google_project_iam_binding" "project-123" {
 	project = "project-123"
 	role    = "roles/iam.serviceAccountTokenCreator"
 }
 `,
}

var terraformNoProjectLevelServiceAccountImpersonationLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam`,
}

var terraformNoProjectLevelServiceAccountImpersonationRemediationMarkdown = ``
