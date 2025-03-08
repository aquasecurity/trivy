package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptAMIs(modules terraform.Modules) []ec2.AMI {
	var res []ec2.AMI

	for _, block := range modules.GetDatasByType("aws_ami") {
		res = append(res, adaptAMI(block))
	}
	return res
}

func adaptAMI(block *terraform.Block) ec2.AMI {
	return ec2.AMI{
		Metadata: block.GetMetadata(),
		Owners:   block.GetAttribute("owners").AsStringValues(),
	}
}
