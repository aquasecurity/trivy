package repositories

var terraformPrivateGoodExamples = []string{
	`
 resource "github_repository" "good_example" {
   name        = "example"
   description = "My awesome codebase"
 
   visibility  = "private"
 
   template {
     owner = "github"
     repository = "terraform-module-template"
   }
 }
 `,
}

var terraformPrivateBadExamples = []string{
	`
 resource "github_repository" "bad_example" {
   name        = "example"
   description = "My awesome codebase"
 
   visibility  = "public"
 
   template {
     owner = "github"
     repository = "terraform-module-template"
   }
 }
 `,
}

var terraformPrivateLinks = []string{
	`https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository`,
}

var terraformPrivateRemediationMarkdown = ``
