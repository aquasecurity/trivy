package compute

var terraformNoPublicAccessGoodExamples = []string{
	`
 resource "openstack_fw_rule_v1" "rule_1" {
 	name                   = "my_rule"
 	description            = "don't let just anyone in"
 	action                 = "allow"
 	protocol               = "tcp"
 	destination_ip_address = "10.10.10.1"
 	source_ip_address      = "10.10.10.2"
 	destination_port       = "22"
 	enabled                = "true"
 }
 			`,
}

var terraformNoPublicAccessBadExamples = []string{
	`
 resource "openstack_fw_rule_v1" "rule_1" {
 	name             = "my_rule"
 	description      = "let anyone in"
 	action           = "allow"
 	protocol         = "tcp"
 	destination_port = "22"
 	enabled          = "true"
 }
 			`,
}

var terraformNoPublicAccessLinks = []string{
	`https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1`,
}

var terraformNoPublicAccessRemediationMarkdown = ``
