package iam

var terraformNoUserGrantedPermissionsGoodExamples = []string{
	`
 resource "google_project_iam_binding" "good_example" {
 	members = [
 		"group:test@example.com",
 		]
 }
 
 resource "google_storage_bucket_iam_member" "good_example" {
 	member = "serviceAccount:test@example.com"
 }`,
}

var terraformNoUserGrantedPermissionsBadExamples = []string{
	`
 resource "google_project_iam_binding" "bad_example" {
 	members = [
 		"user:test@example.com",
 		]
 }
 
 resource "google_project_iam_member" "bad_example" {
 	member = "user:test@example.com"
 }
 `,
}

var terraformNoUserGrantedPermissionsLinks = []string{
	`https://www.terraform.io/docs/providers/google/d/iam_policy.html#members`,
}

var terraformNoUserGrantedPermissionsRemediationMarkdown = ``
