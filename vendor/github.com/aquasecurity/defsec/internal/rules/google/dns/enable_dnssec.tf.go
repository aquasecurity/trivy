package dns

var terraformEnableDnssecGoodExamples = []string{
	`
 resource "google_dns_managed_zone" "good_example" {
   name        = "example-zone"
   dns_name    = "example-${random_id.rnd.hex}.com."
   description = "Example DNS zone"
   labels = {
     foo = "bar"
   }
   dnssec_config {
     state = "on"
   }
 }
 
 resource "random_id" "rnd" {
   byte_length = 4
 }
 `,
}

var terraformEnableDnssecBadExamples = []string{
	`
 resource "google_dns_managed_zone" "bad_example" {
   name        = "example-zone"
   dns_name    = "example-${random_id.rnd.hex}.com."
   description = "Example DNS zone"
   labels = {
     foo = "bar"
   }
   dnssec_config {
     state = "off"
   }
 }
 
 resource "random_id" "rnd" {
   byte_length = 4
 }
 `,
}

var terraformEnableDnssecLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#state`,
}

var terraformEnableDnssecRemediationMarkdown = ``
