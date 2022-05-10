package iam

var terraformNoOrgLevelServiceAccountImpersonationGoodExamples = []string{
	`
 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/nothingInParticular"
 }
 			`,
}

var terraformNoOrgLevelServiceAccountImpersonationBadExamples = []string{
	`
 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/iam.serviceAccountUser"
 }
 `, `
 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/iam.serviceAccountTokenCreator"
 }
 `,
}

var terraformNoOrgLevelServiceAccountImpersonationLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam`,
}

var terraformNoOrgLevelServiceAccountImpersonationRemediationMarkdown = ``
