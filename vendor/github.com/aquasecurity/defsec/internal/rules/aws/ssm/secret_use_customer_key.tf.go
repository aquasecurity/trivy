package ssm

var terraformSecretUseCustomerKeyGoodExamples = []string{
	`
 resource "aws_kms_key" "secrets" {
 	enable_key_rotation = true
 }
 
 resource "aws_secretsmanager_secret" "good_example" {
   name       = "lambda_password"
   kms_key_id = aws_kms_key.secrets.arn
 }
 `,
}

var terraformSecretUseCustomerKeyBadExamples = []string{
	`
 resource "aws_secretsmanager_secret" "bad_example" {
   name       = "lambda_password"
 }
 `,
}

var terraformSecretUseCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id`,
}

var terraformSecretUseCustomerKeyRemediationMarkdown = ``
