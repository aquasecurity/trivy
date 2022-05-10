package compute

var terraformEnforceHttpsGoodExamples = []string{
	`
 resource "digitalocean_loadbalancer" "bad_example" {
   name   = "bad_example-1"
   region = "nyc3"
   
   forwarding_rule {
 	entry_port     = 443
 	entry_protocol = "https"
   
 	target_port     = 443
 	target_protocol = "https"
   }
   
   droplet_ids = [digitalocean_droplet.web.id]
 }
 `,
}

var terraformEnforceHttpsBadExamples = []string{
	`
 resource "digitalocean_loadbalancer" "bad_example" {
   name   = "bad_example-1"
   region = "nyc3"
 
   forwarding_rule {
     entry_port     = 80
     entry_protocol = "http"
 
     target_port     = 80
     target_protocol = "http"
   }
 
   droplet_ids = [digitalocean_droplet.web.id]
 }
 `,
}

var terraformEnforceHttpsLinks = []string{
	`https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/loadbalancer`,
}

var terraformEnforceHttpsRemediationMarkdown = ``
