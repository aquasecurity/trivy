package gke

var terraformEnforcePodSecurityPolicyGoodExamples = []string{
	`
 resource "google_container_cluster" "good_example" {
 	pod_security_policy_config {
         enabled = "true"
 	}
 }`,
}

var terraformEnforcePodSecurityPolicyBadExamples = []string{
	`
 resource "google_container_cluster" "bad_example" {
 	pod_security_policy_config {
         enabled = "false"
 	}
 }`,
}

var terraformEnforcePodSecurityPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#pod_security_policy_config`,
}

var terraformEnforcePodSecurityPolicyRemediationMarkdown = ``
