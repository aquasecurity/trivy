package apigateway

var terraformUseSecureTlsPolicyGoodExamples = []string{
	`
 resource "aws_api_gateway_domain_name" "good_example" {
 	security_policy = "TLS_1_2"
 }
 `,
}

var terraformUseSecureTlsPolicyBadExamples = []string{
	`
 resource "aws_api_gateway_domain_name" "bad_example" {
 	security_policy = "TLS_1_0"
 }
 `,
}

var terraformUseSecureTlsPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy`,
}

var terraformUseSecureTlsPolicyRemediationMarkdown = ``
