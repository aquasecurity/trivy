package iam

var terraformNoDefaultNetworkGoodExamples = []string{
	`
 resource "google_project" "good_example" {
   name       = "My Project"
   project_id = "your-project-id"
   org_id     = "1234567"
   auto_create_network = false
 }
 `,
}

var terraformNoDefaultNetworkBadExamples = []string{
	`
 resource "google_project" "bad_example" {
   name       = "My Project"
   project_id = "your-project-id"
   org_id     = "1234567"
   auto_create_network = true
 }
 `,
}

var terraformNoDefaultNetworkLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project#auto_create_network`,
}

var terraformNoDefaultNetworkRemediationMarkdown = ``
