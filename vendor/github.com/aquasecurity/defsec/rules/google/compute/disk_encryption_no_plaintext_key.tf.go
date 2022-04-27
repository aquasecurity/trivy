package compute

var terraformDiskEncryptionNoPlaintextKeyGoodExamples = []string{
	`
 resource "google_compute_disk" "good_example" {
 	disk_encryption_key {
 		kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
 	}
 }
 `,
}

var terraformDiskEncryptionNoPlaintextKeyBadExamples = []string{
	`
 resource "google_compute_disk" "good_example" {
 	disk_encryption_key {
 		raw_key="b2ggbm8gdGhpcyBpcyBiYWQ="
 	}
 }
 `,
}

var terraformDiskEncryptionNoPlaintextKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link`,
}

var terraformDiskEncryptionNoPlaintextKeyRemediationMarkdown = ``
