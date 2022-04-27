package dynamodb

var terraformEnableRecoveryGoodExamples = []string{
	`
 resource "aws_dynamodb_table" "good_example" {
 	name             = "example"
 	hash_key         = "TestTableHashKey"
 	billing_mode     = "PAY_PER_REQUEST"
 	stream_enabled   = true
 	stream_view_type = "NEW_AND_OLD_IMAGES"
   
 	attribute {
 	  name = "TestTableHashKey"
 	  type = "S"
 	}
 
 	point_in_time_recovery {
 		enabled = true
 	}
 }
 `,
}

var terraformEnableRecoveryBadExamples = []string{
	`
 resource "aws_dynamodb_table" "bad_example" {
 	name             = "example"
 	hash_key         = "TestTableHashKey"
 	billing_mode     = "PAY_PER_REQUEST"
 	stream_enabled   = true
 	stream_view_type = "NEW_AND_OLD_IMAGES"
   
 	attribute {
 	  name = "TestTableHashKey"
 	  type = "S"
 	}
 }
 `,
}

var terraformEnableRecoveryLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#point_in_time_recovery`,
}

var terraformEnableRecoveryRemediationMarkdown = ``
