package compute

var terraformNoIpForwardingGoodExamples = []string{
	`
 resource "google_compute_instance" "bad_example" {
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
   
   can_ip_forward = false
 }
 `,
}

var terraformNoIpForwardingBadExamples = []string{
	`
 resource "google_compute_instance" "bad_example" {
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
 
   can_ip_forward = true
 }
 `,
}

var terraformNoIpForwardingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#can_ip_forward`,
}

var terraformNoIpForwardingRemediationMarkdown = ``
