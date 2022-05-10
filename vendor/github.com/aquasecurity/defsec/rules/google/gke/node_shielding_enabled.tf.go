package gke

var terraformNodeShieldingEnabledGoodExamples = []string{
	`
 resource "google_container_cluster" "good_example" {
 	enable_shielded_nodes = "true"
 }`,
}

var terraformNodeShieldingEnabledBadExamples = []string{
	`
 resource "google_container_cluster" "bad_example" {
 	enable_shielded_nodes = "false"
 }`,
}

var terraformNodeShieldingEnabledLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes`,
}

var terraformNodeShieldingEnabledRemediationMarkdown = ``
