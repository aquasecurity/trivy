package ecr

var terraformEnableImageScansGoodExamples = []string{
	`
 resource "aws_ecr_repository" "good_example" {
   name                 = "bar"
   image_tag_mutability = "MUTABLE"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 `,
}

var terraformEnableImageScansBadExamples = []string{
	`
 resource "aws_ecr_repository" "bad_example" {
   name                 = "bar"
   image_tag_mutability = "MUTABLE"
 
   image_scanning_configuration {
     scan_on_push = false
   }
 }
 `,
}

var terraformEnableImageScansLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#image_scanning_configuration`,
}

var terraformEnableImageScansRemediationMarkdown = ``
