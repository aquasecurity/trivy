package ecs

var terraformNoPlaintextSecretsGoodExamples = []string{
	`
 resource "aws_ecs_task_definition" "good_example" {
   container_definitions = <<EOF
 [
   {
     "name": "my_service",
     "essential": true,
     "memory": 256,
     "environment": [
       { "name": "ENVIRONMENT", "value": "development" }
     ]
   }
 ]
 EOF
 
 }
 `,
}

var terraformNoPlaintextSecretsBadExamples = []string{
	`
 resource "aws_ecs_task_definition" "bad_example" {
   container_definitions = <<EOF
 [
   {
     "name": "my_service",
     "essential": true,
     "memory": 256,
     "environment": [
       { "name": "ENVIRONMENT", "value": "development" },
       { "name": "DATABASE_PASSWORD", "value": "oh no D:"}
     ]
   }
 ]
 EOF
 
 }
 `,
}

var terraformNoPlaintextSecretsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition`,
}

var terraformNoPlaintextSecretsRemediationMarkdown = ``
