package spaces

var terraformDisableForceDestroyGoodExamples = []string{
	`
 resource "digitalocean_spaces_bucket" "good_example" {
   name   = "foobar"
   region = "nyc3"
 }
 `,
}

var terraformDisableForceDestroyBadExamples = []string{
	`
 resource "digitalocean_spaces_bucket" "bad_example" {
   name   		= "foobar"
   region 		= "nyc3"
   force_destroy = true
 }
 `,
}

var terraformDisableForceDestroyLinks = []string{
	`https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#force_destroy`,
}

var terraformDisableForceDestroyRemediationMarkdown = ``
