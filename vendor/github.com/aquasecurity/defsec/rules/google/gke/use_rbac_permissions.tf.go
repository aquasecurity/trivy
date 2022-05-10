package gke

var terraformUseRbacPermissionsGoodExamples = []string{
	`
 resource "google_container_cluster" "good_example" {
 	# ...
 	# enable_legacy_abac not set
 	# ...
 }
 `,
}

var terraformUseRbacPermissionsBadExamples = []string{
	`
 resource "google_container_cluster" "bad_example" {
 	enable_legacy_abac = "true"
 }
 `,
}

var terraformUseRbacPermissionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac`,
}

var terraformUseRbacPermissionsRemediationMarkdown = ``
