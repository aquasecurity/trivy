package compute

var terraformNoPlaintextPasswordGoodExamples = []string{
	`
 resource "openstack_compute_instance_v2" "good_example" {
   name            = "basic"
   image_id        = "ad091b52-742f-469e-8f3c-fd81cadf0743"
   flavor_id       = "3"
   key_pair        = "my_key_pair_name"
   security_groups = ["default"]
   user_data       = "#cloud-config\nhostname: instance_1.example.com\nfqdn: instance_1.example.com"
 
   network {
     name = "my_network"
   }
 }`,
}

var terraformNoPlaintextPasswordBadExamples = []string{
	`
 resource "openstack_compute_instance_v2" "bad_example" {
   name            = "basic"
   image_id        = "ad091b52-742f-469e-8f3c-fd81cadf0743"
   flavor_id       = "3"
   admin_pass      = "N0tSoS3cretP4ssw0rd"
   security_groups = ["default"]
   user_data       = "#cloud-config\nhostname: instance_1.example.com\nfqdn: instance_1.example.com"
 
   network {
     name = "my_network"
   }
 }`,
}

var terraformNoPlaintextPasswordLinks = []string{
	`https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/compute_instance_v2#admin_pass`,
}

var terraformNoPlaintextPasswordRemediationMarkdown = ``
