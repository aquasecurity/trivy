package compute

var terraformNoPublicIngressGoodExamples = []string{
	`
resource "google_compute_firewall" "good_example" {
  source_ranges = ["1.2.3.4/32"]
  allow {
    protocol = "icmp"
  }
}`,
}

var terraformNoPublicIngressBadExamples = []string{
	`
resource "google_compute_firewall" "bad_example" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "icmp"
  }
}`,
}

var terraformNoPublicIngressLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges`, `https://www.terraform.io/docs/providers/google/r/compute_firewall.html`,
}

var terraformNoPublicIngressRemediationMarkdown = ``
