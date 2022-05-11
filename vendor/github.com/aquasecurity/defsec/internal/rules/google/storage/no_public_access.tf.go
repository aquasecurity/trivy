package storage

var terraformNoPublicAccessGoodExamples = []string{
	`
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"user:jane@example.com",
 	]
 }
 			`,
}

var terraformNoPublicAccessBadExamples = []string{
	`
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"allAuthenticatedUsers",
 	]
 }
 			`,
}

var terraformNoPublicAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#member/members`,
}

var terraformNoPublicAccessRemediationMarkdown = ``
