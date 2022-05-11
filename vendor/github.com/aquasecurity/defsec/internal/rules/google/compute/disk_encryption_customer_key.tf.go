package compute

var terraformDiskEncryptionCustomerKeyGoodExamples = []string{
	`
 resource "google_compute_disk" "good_example" {
   name  = "test-disk"
   type  = "pd-ssd"
   zone  = "us-central1-a"
   image = "debian-9-stretch-v20200805"
   labels = {
     environment = "dev"
   }
   physical_block_size_bytes = 4096
   disk_encryption_key {
     kms_key_self_link = "something"
   }
 }
 `,
}

var terraformDiskEncryptionCustomerKeyBadExamples = []string{
	`
 resource "google_compute_disk" "bad_example" {
   name  = "test-disk"
   type  = "pd-ssd"
   zone  = "us-central1-a"
   image = "debian-9-stretch-v20200805"
   labels = {
     environment = "dev"
   }
   physical_block_size_bytes = 4096
 }
 `,
}

var terraformDiskEncryptionCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link`,
}

var terraformDiskEncryptionCustomerKeyRemediationMarkdown = ``
