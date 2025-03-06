package ami

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ami"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(cfFile parser.FileContext) ami.AMI {
	return ami.AMI{
		Metadata: cfFile.Metadata(),
		Owners:   adaptAMIs(cfFile),
	}
}

func adaptAMIs(cfFile parser.FileContext) iacTypes.StringValueList {
	var owners iacTypes.StringValueList

	amis := cfFile.GetResourcesByType("AWS::EC2::Image")
	for _, resource := range amis {
		owners = append(owners, resource.GetStringProperty("Owners"))
	}

	return owners
}
