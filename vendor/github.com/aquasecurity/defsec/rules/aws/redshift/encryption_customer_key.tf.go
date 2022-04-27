package redshift

var terraformEncryptionCustomerKeyGoodExamples = []string{
	`
 resource "aws_kms_key" "redshift" {
 	enable_key_rotation = true
 }
 
 resource "aws_redshift_cluster" "good_example" {
   cluster_identifier = "tf-redshift-cluster"
   database_name      = "mydb"
   master_username    = "foo"
   master_password    = "Mustbe8characters"
   node_type          = "dc1.large"
   cluster_type       = "single-node"
   encrypted          = true
   kms_key_id         = aws_kms_key.redshift.key_id
 }
 `,
}

var terraformEncryptionCustomerKeyBadExamples = []string{
	`
 resource "aws_redshift_cluster" "bad_example" {
   cluster_identifier = "tf-redshift-cluster"
   database_name      = "mydb"
   master_username    = "foo"
   master_password    = "Mustbe8characters"
   node_type          = "dc1.large"
   cluster_type       = "single-node"
 }
 `,
}

var terraformEncryptionCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted`,
}

var terraformEncryptionCustomerKeyRemediationMarkdown = ``
