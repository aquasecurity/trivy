package vpc

var terraformNoDefaultVpcGoodExamples = []string{
	`
 # no aws default vpc present
 `,
}

var terraformNoDefaultVpcBadExamples = []string{
	`
 resource "aws_default_vpc" "default" {
 	tags = {
 	  Name = "Default VPC"
 	}
   }
 `,
}

var terraformNoDefaultVpcLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc`,
}

var terraformNoDefaultVpcRemediationMarkdown = ``
