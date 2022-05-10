package compute

var terraformNoPublicEgressGoodExamples = []string{
	`
resource "openstack_networking_secgroup_rule_v2" "rule_1" {
	direction         = "egress"
	ethertype         = "IPv4"
	protocol          = "tcp"
	port_range_min    = 22
	port_range_max    = 22
	remote_ip_prefix  = "1.2.3.4/32"
}
`,
}

var terraformNoPublicEgressBadExamples = []string{
	`
 resource "openstack_networking_secgroup_rule_v2" "rule_1" {
	direction         = "egress"
	ethertype         = "IPv4"
	protocol          = "tcp"
	port_range_min    = 22
	port_range_max    = 22
	remote_ip_prefix  = "0.0.0.0/0"
 }
`,
}

var terraformNoPublicEgressLinks = []string{
	`https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2`,
}

var terraformNoPublicEgressRemediationMarkdown = ``
