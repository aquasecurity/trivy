package dynamodb

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "aws_dax_cluster" "good_example" {
 	// other DAX config
 
 	server_side_encryption {
 		enabled = true // enabled server side encryption
 	}
 }
 `,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
 resource "aws_dax_cluster" "bad_example" {
 	// no server side encryption at all
 }
 
 resource "aws_dax_cluster" "bad_example" {
 	// other DAX config
 
 	server_side_encryption {
 		// empty server side encryption config
 	}
 }
 
 resource "aws_dax_cluster" "bad_example" {
 	// other DAX config
 
 	server_side_encryption {
 		enabled = false // disabled server side encryption
 	}
 }
 `,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
