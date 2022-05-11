package compute

var terraformNoPublicIngressGoodExamples = []string{
	`
 resource "openstack_networking_secgroup_rule_v2" "rule_1" {
	direction         = "ingress"
	ethertype         = "IPv4"
	protocol          = "tcp"
	port_range_min    = 22
	port_range_max    = 22
	remote_ip_prefix  = "1.2.3.4/32"
 }
 			`,
}

var terraformNoPublicIngressBadExamples = []string{
	`
 resource "openstack_networking_secgroup_rule_v2" "rule_1" {
	direction         = "ingress"
	ethertype         = "IPv4"
	protocol          = "tcp"
	port_range_min    = 22
	port_range_max    = 22
	remote_ip_prefix  = "0.0.0.0/0"
 }
 			`,
}

var terraformNoPublicIngressLinks = []string{
	`https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1`,
}

var terraformNoPublicIngressRemediationMarkdown = ``
