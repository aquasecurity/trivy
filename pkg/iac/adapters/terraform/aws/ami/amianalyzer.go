package ami

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ami"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) ami.AMI {
	return ami.AMI{
		Owners: adaptAMIs(modules),
	}
}

func adaptAMIs(modules terraform.Modules) iacTypes.StringValueList {
	var owners iacTypes.StringValueList

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ami") {
			owners = append(owners, adaptOwners(resource)...)
		}
	}
	return owners
}

func adaptOwners(resource *terraform.Block) iacTypes.StringValueList {
	ownersAttr := resource.GetAttribute("owners")
	return ownersAttr.AsStringValuesOrDefault(resource, "")
}
