package elasticache

var terraformAddDescriptionForSecurityGroupGoodExamples = []string{
	`
resource "aws_security_group" "bar" {
	name = "security-group"
}

resource "aws_elasticache_security_group" "good_example" {
	name = "elasticache-security-group"
	security_group_names = [aws_security_group.bar.name]
	description = "something"
}
	`,
}

var terraformAddDescriptionForSecurityGroupBadExamples = []string{
	`
resource "aws_security_group" "bar" {
	name = "security-group"
}

resource "aws_elasticache_security_group" "bad_example" {
	name = "elasticache-security-group"
	security_group_names = [aws_security_group.bar.name]
	description = ""
}
		`,
}

var terraformAddDescriptionForSecurityGroupLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_security_group#description`,
}

var terraformAddDescriptionForSecurityGroupRemediationMarkdown = ``
