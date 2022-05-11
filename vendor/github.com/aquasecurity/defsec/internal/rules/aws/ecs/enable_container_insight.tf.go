package ecs

var terraformEnableContainerInsightGoodExamples = []string{
	`
 resource "aws_ecs_cluster" "good_example" {
 	name = "services-cluster"
   
 	setting {
 	  name  = "containerInsights"
 	  value = "enabled"
 	}
 }
 `,
}

var terraformEnableContainerInsightBadExamples = []string{
	`
 resource "aws_ecs_cluster" "bad_example" {
   	name = "services-cluster"
 }
 `,
}

var terraformEnableContainerInsightLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster#setting`,
}

var terraformEnableContainerInsightRemediationMarkdown = ``
