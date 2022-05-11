package gke

var terraformMetadataEndpointsDisabledGoodExamples = []string{
	`
 resource "google_container_cluster" "good_example" {
    node_config {
      metadata {
        disable-legacy-endpoints = true
      }
    }
 }`,
}

var terraformMetadataEndpointsDisabledBadExamples = []string{
	`
 resource "google_container_cluster" "bad_example" {
    node_config {
      metadata {
        disable-legacy-endpoints = false
      }
    }
 }`,
}

var terraformMetadataEndpointsDisabledLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata`,
}

var terraformMetadataEndpointsDisabledRemediationMarkdown = ``
