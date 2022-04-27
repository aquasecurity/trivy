package autoscaling

var terraformNoSensitiveInfoGoodExamples = []string{
	`
 resource "aws_launch_configuration" "as_conf" {
   name          = "web_config"
   image_id      = data.aws_ami.ubuntu.id
   instance_type = "t2.micro"
   user_data     = <<EOF
 export GREETING="Hello there"
 EOF
 }
 `, `
 resource "aws_launch_configuration" "as_conf" {
 	name             = "web_config"
 	image_id         = data.aws_ami.ubuntu.id
 	instance_type    = "t2.micro"
 	user_data_base64 = "ZXhwb3J0IEVESVRPUj12aW1hY3M="
   }
   `,
}

var terraformNoSensitiveInfoBadExamples = []string{
	`
 resource "aws_launch_configuration" "as_conf" {
   name          = "web_config"
   image_id      = data.aws_ami.ubuntu.id
   instance_type = "t2.micro"
   user_data     = <<EOF
 export DATABASE_PASSWORD=\"SomeSortOfPassword\"
 EOF
 }
 `, `
 resource "aws_launch_configuration" "as_conf" {
   name             = "web_config"
   image_id         = data.aws_ami.ubuntu.id
   instance_type    = "t2.micro"
   user_data_base64 = "ZXhwb3J0IERBVEFCQVNFX1BBU1NXT1JEPSJTb21lU29ydE9mUGFzc3dvcmQi"
 }
 `,
}

var terraformNoSensitiveInfoLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#user_data,user_data_base64`,
}

var terraformNoSensitiveInfoRemediationMarkdown = ``
