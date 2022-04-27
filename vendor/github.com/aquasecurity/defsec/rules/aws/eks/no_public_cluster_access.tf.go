package eks

var terraformNoPublicClusterAccessGoodExamples = []string{
	`
 resource "aws_eks_cluster" "good_example" {
     // other config 
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 `,
}

var terraformNoPublicClusterAccessBadExamples = []string{
	`
 resource "aws_eks_cluster" "bad_example" {
     // other config 
 
     name = "bad_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
 		endpoint_public_access = true
 		public_access_cidrs = ["0.0.0.0/0"]
     }
 }
 `,
}

var terraformNoPublicClusterAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_public_access`,
}

var terraformNoPublicClusterAccessRemediationMarkdown = ``
