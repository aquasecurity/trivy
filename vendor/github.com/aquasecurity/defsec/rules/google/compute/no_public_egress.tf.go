package compute

var terraformNoPublicEgressGoodExamples = []string{
	`
 resource "google_compute_firewall" "good_example" {
  direction = "EGRESS"
  allow {
    protocol = "icmp"
  }
  destination_ranges = ["1.2.3.4/32"]
}`,
}

var terraformNoPublicEgressBadExamples = []string{
	`
resource "google_compute_firewall" "bad_example" {
  direction = "EGRESS"
  allow {
    protocol = "icmp"
  }
  destination_ranges = ["0.0.0.0/0"]
}`,
}

var terraformNoPublicEgressLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall`,
}

var terraformNoPublicEgressRemediationMarkdown = ``
