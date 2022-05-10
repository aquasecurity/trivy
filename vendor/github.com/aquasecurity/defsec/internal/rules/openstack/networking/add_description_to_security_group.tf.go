package compute

var terraformSecurityGroupHasDescriptionGoodExamples = []string{
	`
 resource "openstack_networking_secgroup_v2" "group_1" {
 	description            = "don't let just anyone in"
 }
 			`,
}

var terraformSecurityGroupHasDescriptionBadExamples = []string{
	`
 resource "openstack_networking_secgroup_v2" "group_1" {
 }
 			`,
}

var terraformSecurityGroupHasDescriptionLinks = []string{}

var terraformSecurityGroupHasDescriptionRemediationMarkdown = ``
