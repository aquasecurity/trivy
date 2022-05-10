package gke

var terraformUseServiceAccountGoodExamples = []string{
	`
 resource "google_container_cluster" "good_example" {
 	node_config {
 		service_account = "cool-service-account@example.com"
 	}
 }
 `,
}

var terraformUseServiceAccountBadExamples = []string{
	`
 resource "google_container_cluster" "bad_example" {
 	node_config {
 	}
 }
 `,
}

var terraformUseServiceAccountLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account`,
}

var terraformUseServiceAccountRemediationMarkdown = ``
