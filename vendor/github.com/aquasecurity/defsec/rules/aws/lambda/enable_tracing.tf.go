package lambda

var terraformEnableTracingGoodExamples = []string{
	`
 resource "aws_iam_role" "iam_for_lambda" {
   name = "iam_for_lambda"
 
   assume_role_policy = <<EOF
 {
   "Version": "2012-10-17",
   "Statement": [
     {
       "Action": "sts:AssumeRole",
       "Principal": {
         "Service": "lambda.amazonaws.com"
       },
       "Effect": "Allow",
       "Sid": ""
     }
   ]
 }
 EOF
 }
 
 resource "aws_lambda_function" "good_example" {
   filename      = "lambda_function_payload.zip"
   function_name = "lambda_function_name"
   role          = aws_iam_role.iam_for_lambda.arn
   handler       = "exports.test"
 
   # The filebase64sha256() function is available in Terraform 0.11.12 and later
   # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
   # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
   source_code_hash = filebase64sha256("lambda_function_payload.zip")
 
   runtime = "nodejs12.x"
 
   environment {
     variables = {
       foo = "bar"
     }
   }
   tracing_config {
     mode = "Active"
   }
 }
 `,
}

var terraformEnableTracingBadExamples = []string{
	`
 resource "aws_iam_role" "iam_for_lambda" {
   name = "iam_for_lambda"
 
   assume_role_policy = <<EOF
 {
   "Version": "2012-10-17",
   "Statement": [
     {
       "Action": "sts:AssumeRole",
       "Principal": {
         "Service": "lambda.amazonaws.com"
       },
       "Effect": "Allow",
       "Sid": ""
     }
   ]
 }
 EOF
 }
 
 resource "aws_lambda_function" "bad_example" {
   filename      = "lambda_function_payload.zip"
   function_name = "lambda_function_name"
   role          = aws_iam_role.iam_for_lambda.arn
   handler       = "exports.test"
 
   # The filebase64sha256() function is available in Terraform 0.11.12 and later
   # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
   # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
   source_code_hash = filebase64sha256("lambda_function_payload.zip")
 
   runtime = "nodejs12.x"
 
   environment {
     variables = {
       foo = "bar"
     }
   }
   tracing_config {
     mode = "Passthrough"
   }
 }
 `,
}

var terraformEnableTracingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#mode`,
}

var terraformEnableTracingRemediationMarkdown = ``
