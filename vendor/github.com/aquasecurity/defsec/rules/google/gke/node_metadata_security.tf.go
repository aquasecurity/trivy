package gke

var terraformNodeMetadataSecurityGoodExamples = []string{
	`
 resource "google_container_node_pool" "good_example" {
 	node_config {
 		workload_metadata_config {
 			node_metadata = "SECURE"
 		}
 	}
 }`,
}

var terraformNodeMetadataSecurityBadExamples = []string{
	`
 resource "google_container_node_pool" "bad_example" {
 	node_config {
 		workload_metadata_config {
 			node_metadata = "EXPOSE"
 		}
 	}
 }`,
}

var terraformNodeMetadataSecurityLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_metadata`,
}

var terraformNodeMetadataSecurityRemediationMarkdown = ``
