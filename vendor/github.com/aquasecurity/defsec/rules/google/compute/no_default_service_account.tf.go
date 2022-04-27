package compute

var terraformNoDefaultServiceAccountGoodExamples = []string{
	`
 resource "google_service_account" "default" {
   account_id   = "service_account_id"
   display_name = "Service Account"
 }
 
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   network_interface {
     network = "default"
 
     access_config {
       // Ephemeral IP
     }
   }
 
   metadata = {
     foo = "bar"
   }
 
   metadata_startup_script = "echo hi > /test.txt"
 
   service_account {
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     email  = google_service_account.default.email
     scopes = ["cloud-platform"]
   }
 }
 `,
}

var terraformNoDefaultServiceAccountBadExamples = []string{
	`
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   service_account {
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     email  = "1234567890-compute@developer.gserviceaccount.com"
     scopes = ["cloud-platform"]
   }
 }
 `,
}

var terraformNoDefaultServiceAccountLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#`,
}

var terraformNoDefaultServiceAccountRemediationMarkdown = ``
