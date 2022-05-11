package apigateway

var terraformNoPublicAccessGoodExamples = []string{
	`
 resource "aws_api_gateway_rest_api" "MyDemoAPI" {
	
 }

 resource "aws_api_gateway_method" "good_example" {
   rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
   resource_id   = aws_api_gateway_resource.MyDemoResource.id
   http_method   = "GET"
   authorization = "AWS_IAM"
 }
 `, `
 resource "aws_api_gateway_rest_api" "MyDemoAPI" {
	
 }

 resource "aws_api_gateway_method" "good_example" {
   rest_api_id      = aws_api_gateway_rest_api.MyDemoAPI.id
   resource_id      = aws_api_gateway_resource.MyDemoResource.id
   http_method      = "GET"
   authorization    = "NONE"
   api_key_required = true
 }
 `, `
 resource "aws_api_gateway_rest_api" "MyDemoAPI" {
	
 }

 resource "aws_api_gateway_method" "good_example" {
   rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
   resource_id   = aws_api_gateway_resource.MyDemoResource.id
   http_method   = "OPTION"
   authorization = "NONE"
 }
 `,
}

var terraformNoPublicAccessBadExamples = []string{
	`
 resource "aws_api_gateway_rest_api" "MyDemoAPI" {
	
 }

 resource "aws_api_gateway_method" "bad_example" {
   rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
   resource_id   = aws_api_gateway_resource.MyDemoResource.id
   http_method   = "GET"
   authorization = "NONE"
 }
 `,
}

var terraformNoPublicAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method#authorization`,
}

var terraformNoPublicAccessRemediationMarkdown = ``
