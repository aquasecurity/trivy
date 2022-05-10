package ecr

var terraformEnforceImmutableRepositoryGoodExamples = []string{
	`
 resource "aws_ecr_repository" "good_example" {
   name                 = "bar"
   image_tag_mutability = "IMMUTABLE"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 `,
}

var terraformEnforceImmutableRepositoryBadExamples = []string{
	`
 resource "aws_ecr_repository" "bad_example" {
   name                 = "bar"
   image_tag_mutability = "MUTABLE"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 `,
}

var terraformEnforceImmutableRepositoryLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository`,
}

var terraformEnforceImmutableRepositoryRemediationMarkdown = ``
