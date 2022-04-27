package ecr

var terraformRepositoryCustomerKeyGoodExamples = []string{
	`
 resource "aws_kms_key" "ecr_kms" {
 	enable_key_rotation = true
 }
 
 resource "aws_ecr_repository" "good_example" {
 	name                 = "bar"
 	image_tag_mutability = "MUTABLE"
   
 	image_scanning_configuration {
 	  scan_on_push = true
 	}
 
 	encryption_configuration {
 		encryption_type = "KMS"
 		kms_key = aws_kms_key.ecr_kms.key_id
 	}
   }
 `,
}

var terraformRepositoryCustomerKeyBadExamples = []string{
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

var terraformRepositoryCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration`,
}

var terraformRepositoryCustomerKeyRemediationMarkdown = ``
