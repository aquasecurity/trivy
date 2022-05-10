package compute

var terraformNoPublicEgressGoodExamples = []string{
	`
 resource "digitalocean_firewall" "good_example" {
 	name = "only-22-80-and-443"
   
 	droplet_ids = [digitalocean_droplet.web.id]
   
 	outbound_rule {
 	  protocol         = "tcp"
 	  port_range       = "22"
 	  destination_addresses = ["192.168.1.0/24", "fc00::/7"]
 	}
 }
 `,
}

var terraformNoPublicEgressBadExamples = []string{
	`
 resource "digitalocean_firewall" "bad_example" {
 	name = "only-22-80-and-443"
   
 	droplet_ids = [digitalocean_droplet.web.id]
   
 	outbound_rule {
 	  protocol         = "tcp"
 	  port_range       = "22"
 	  destination_addresses = ["0.0.0.0/0", "::/0"]
 	}
 }
 `,
}

var terraformNoPublicEgressLinks = []string{
	`https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall`,
}

var terraformNoPublicEgressRemediationMarkdown = ``
