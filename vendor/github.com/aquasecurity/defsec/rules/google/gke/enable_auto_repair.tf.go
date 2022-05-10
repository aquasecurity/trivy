package gke

var terraformEnableAutoRepairGoodExamples = []string{
	`
 resource "google_service_account" "default" {
   account_id   = "service-account-id"
   display_name = "Service Account"
 }
 
 resource "google_container_cluster" "primary" {
   name     = "my-gke-cluster"
   location = "us-central1"
 
   # We can't create a cluster with no node pool defined, but we want to only use
   # separately managed node pools. So we create the smallest possible default
   # node pool and immediately delete it.
   remove_default_node_pool = true
   initial_node_count       = 1
 }
 
 resource "google_container_node_pool" "good_example" {
   name       = "my-node-pool"
   cluster    = google_container_cluster.primary.id
   node_count = 1
 
   node_config {
     preemptible  = true
     machine_type = "e2-medium"
 
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     service_account = google_service_account.default.email
     oauth_scopes = [
       "https://www.googleapis.com/auth/cloud-platform"
     ]
   }
   management {
     auto_repair = true
   }
 }
 `,
}

var terraformEnableAutoRepairBadExamples = []string{
	`
 resource "google_service_account" "default" {
   account_id   = "service-account-id"
   display_name = "Service Account"
 }
 
 resource "google_container_cluster" "primary" {
   name     = "my-gke-cluster"
   location = "us-central1"
 
   # We can't create a cluster with no node pool defined, but we want to only use
   # separately managed node pools. So we create the smallest possible default
   # node pool and immediately delete it.
   remove_default_node_pool = true
   initial_node_count       = 1
 }
 
 resource "google_container_node_pool" "bad_example" {
   name       = "my-node-pool"
   cluster    = google_container_cluster.primary.id
   node_count = 1
 
   node_config {
     preemptible  = true
     machine_type = "e2-medium"
 
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     service_account = google_service_account.default.email
     oauth_scopes = [
       "https://www.googleapis.com/auth/cloud-platform"
     ]
   }
   management {
     auto_repair = false
   }
 }
 `,
}

var terraformEnableAutoRepairLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#auto_repair`,
}

var terraformEnableAutoRepairRemediationMarkdown = ``
