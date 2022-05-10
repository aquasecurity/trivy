package redshift

var terraformUseVpcGoodExamples = []string{
	`
 resource "aws_redshift_cluster" "good_example" {
 	cluster_identifier = "tf-redshift-cluster"
 	database_name      = "mydb"
 	master_username    = "foo"
 	master_password    = "Mustbe8characters"
 	node_type          = "dc1.large"
 	cluster_type       = "single-node"
 
 	cluster_subnet_group_name = "redshift_subnet"
 }
 `,
}

var terraformUseVpcBadExamples = []string{
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

var terraformUseVpcLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#cluster_subnet_group_name`,
}

var terraformUseVpcRemediationMarkdown = ``
