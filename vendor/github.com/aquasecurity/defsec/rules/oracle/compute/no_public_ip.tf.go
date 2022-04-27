package compute

var terraformNoPublicIpGoodExamples = []string{
	`
 resource "opc_compute_ip_address_reservation" "good_example" {
 	name            = "my-ip-address"
 	ip_address_pool = "cloud-ippool"
   }
 `,
}

var terraformNoPublicIpBadExamples = []string{
	`
 resource "opc_compute_ip_address_reservation" "bad_example" {
 	name            = "my-ip-address"
 	ip_address_pool = "public-ippool"
   }
 `,
}

var terraformNoPublicIpLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_ip_address_reservation`, `https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_instance`,
}

var terraformNoPublicIpRemediationMarkdown = ``
