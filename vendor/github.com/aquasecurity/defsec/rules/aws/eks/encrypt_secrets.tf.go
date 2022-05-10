package eks

var terraformEncryptSecretsGoodExamples = []string{
	`
 resource "aws_eks_cluster" "good_example" {
     encryption_config {
         resources = [ "secrets" ]
         provider {
             key_arn = var.kms_arn
         }
     }
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 `,
}

var terraformEncryptSecretsBadExamples = []string{
	`
 resource "aws_eks_cluster" "bad_example" {
     name = "bad_example_cluster"
 
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 `,
}

var terraformEncryptSecretsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config`,
}

var terraformEncryptSecretsRemediationMarkdown = ``
