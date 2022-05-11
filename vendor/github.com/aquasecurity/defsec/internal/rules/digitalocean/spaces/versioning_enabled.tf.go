package spaces

var terraformVersioningEnabledGoodExamples = []string{
	`
 resource "digitalocean_spaces_bucket" "good_example" {
   name   = "foobar"
   region = "nyc3"
 
   versioning {
 	enabled = true
   }
 }
 `,
}

var terraformVersioningEnabledBadExamples = []string{
	`
 resource "digitalocean_spaces_bucket" "bad_example" {
   name   = "foobar"
   region = "nyc3"
 }
 
 resource "digitalocean_spaces_bucket" "bad_example" {
   name   = "foobar"
   region = "nyc3"
 
   versioning {
 	enabled = false	
   }
 }
 `,
}

var terraformVersioningEnabledLinks = []string{
	`https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#versioning`,
}

var terraformVersioningEnabledRemediationMarkdown = ``
