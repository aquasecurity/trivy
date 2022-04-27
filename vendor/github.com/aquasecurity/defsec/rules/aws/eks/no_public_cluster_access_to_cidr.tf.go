package eks

var terraformNoPublicClusterAccessToCidrGoodExamples = []string{
	`
 resource "aws_eks_cluster" "good_example" {
     // other config 
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = true
         public_access_cidrs = ["10.2.0.0/8"]
     }
 }
 `,
}

var terraformNoPublicClusterAccessToCidrBadExamples = []string{
	`
 resource "aws_eks_cluster" "bad_example" {
     // other config 
 
     name = "bad_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = true
     }
 }
 `,
}

var terraformNoPublicClusterAccessToCidrLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config`,
}

var terraformNoPublicClusterAccessToCidrRemediationMarkdown = ``
