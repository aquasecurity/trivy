package athena

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "aws_athena_database" "good_example" {
   name   = "database_name"
   bucket = aws_s3_bucket.hoge.bucket
 
   encryption_configuration {
      encryption_option = "SSE_KMS"
      kms_key_arn       = aws_kms_key.example.arn
  }
 }
 
 resource "aws_athena_workgroup" "good_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = true
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
 
       encryption_configuration {
         encryption_option = "SSE_KMS"
         kms_key_arn       = aws_kms_key.example.arn
       }
     }
   }
 }
 `,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
 resource "aws_athena_database" "bad_example" {
   name   = "database_name"
   bucket = aws_s3_bucket.hoge.bucket
 }
 
 resource "aws_athena_workgroup" "bad_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = true
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
     }
   }
 }
 `,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration`, `https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
