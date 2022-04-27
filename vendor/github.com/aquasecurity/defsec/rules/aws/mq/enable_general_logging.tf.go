package mq

var terraformEnableGeneralLoggingGoodExamples = []string{
	`
 resource "aws_mq_broker" "good_example" {
   broker_name = "example"
 
   configuration {
     id       = aws_mq_configuration.test.id
     revision = aws_mq_configuration.test.latest_revision
   }
 
   engine_type        = "ActiveMQ"
   engine_version     = "5.15.0"
   host_instance_type = "mq.t2.micro"
   security_groups    = [aws_security_group.test.id]
 
   user {
     username = "ExampleUser"
     password = "MindTheGap"
   }
   logs {
     general = true
   }
 }
 `,
}

var terraformEnableGeneralLoggingBadExamples = []string{
	`
 resource "aws_mq_broker" "bad_example" {
   broker_name = "example"
 
   configuration {
     id       = aws_mq_configuration.test.id
     revision = aws_mq_configuration.test.latest_revision
   }
 
   engine_type        = "ActiveMQ"
   engine_version     = "5.15.0"
   host_instance_type = "mq.t2.micro"
   security_groups    = [aws_security_group.test.id]
 
   user {
     username = "ExampleUser"
     password = "MindTheGap"
   }
   logs {
     general = false
   }
 }
 `,
}

var terraformEnableGeneralLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#general`,
}

var terraformEnableGeneralLoggingRemediationMarkdown = ``
