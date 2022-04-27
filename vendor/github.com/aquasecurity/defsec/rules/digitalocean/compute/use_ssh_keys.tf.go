package compute

var terraformUseSshKeysGoodExamples = []string{
	`
 data "digitalocean_ssh_key" "terraform" {
 	name = "myKey"
   }
   
 resource "digitalocean_droplet" "good_example" {
 	image    = "ubuntu-18-04-x64"
 	name     = "web-1"
 	region   = "nyc2"
 	size     = "s-1vcpu-1gb"
 	ssh_keys = [ data.digitalocean_ssh_key.myKey.id ]
 }
 `,
}

var terraformUseSshKeysBadExamples = []string{
	`
 resource "digitalocean_droplet" "good_example" {
 	image    = "ubuntu-18-04-x64"
 	name     = "web-1"
 	region   = "nyc2"
 	size     = "s-1vcpu-1gb"
  }
 `,
}

var terraformUseSshKeysLinks = []string{
	`https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/droplet#ssh_keys`,
}

var terraformUseSshKeysRemediationMarkdown = ``
