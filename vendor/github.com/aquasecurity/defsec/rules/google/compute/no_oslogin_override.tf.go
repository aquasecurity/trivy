package compute

var terraformNoOsloginOverrideGoodExamples = []string{
	`
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   metadata = {
   }
 }
 `,
}

var terraformNoOsloginOverrideBadExamples = []string{
	`
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   metadata = {
     enable-oslogin = false
   }
 }
 `,
}

var terraformNoOsloginOverrideLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#`,
}

var terraformNoOsloginOverrideRemediationMarkdown = ``
