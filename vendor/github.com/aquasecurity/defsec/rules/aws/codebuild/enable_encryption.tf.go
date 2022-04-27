package codebuild

var terraformEnableEncryptionGoodExamples = []string{
	`
 resource "aws_codebuild_project" "good_example" {
 	// other config
 
 	artifacts {
 		// other artifacts config
 
 		encryption_disabled = false
 	}
 }
 
 resource "aws_codebuild_project" "good_example" {
 	// other config
 
 	artifacts {
 		// other artifacts config
 	}
 }
 
 resource "aws_codebuild_project" "codebuild" {
 	// other config
 
 	secondary_artifacts {
 		// other artifacts config
 
 		encryption_disabled = false
 	}
 
 	secondary_artifacts {
 		// other artifacts config
 	}
 }
 `,
}

var terraformEnableEncryptionBadExamples = []string{
	`
 resource "aws_codebuild_project" "bad_example" {
 	// other config
 
 	artifacts {
 		// other artifacts config
 
 		encryption_disabled = true
 	}
 }
 
 resource "aws_codebuild_project" "bad_example" {
 	// other config including primary artifacts
 
 	secondary_artifacts {
 		// other artifacts config
 		
 		encryption_disabled = false
 	}
 
 	secondary_artifacts {
 		// other artifacts config
 
 		encryption_disabled = true
 	}
 }
 `,
}

var terraformEnableEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled`,
}

var terraformEnableEncryptionRemediationMarkdown = ``
