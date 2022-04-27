package compute

var terraformProjectLevelOsloginGoodExamples = []string{
	`
 resource "google_compute_project_metadata" "default" {
   metadata = {
     enable-oslogin = true
   }
 }
 `,
}

var terraformProjectLevelOsloginBadExamples = []string{
	`
 resource "google_compute_project_metadata" "default" {
   metadata = {
 	enable-oslogin = false
   }
 }
 `,
}

var terraformProjectLevelOsloginLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#`,
}

var terraformProjectLevelOsloginRemediationMarkdown = ``
