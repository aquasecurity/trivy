package ec2

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

func getVPCs(fctx parser.FileContext) []ec2.VPC {
	vpcFlowLogs := getVpcGlowLogs(fctx)
	return lo.Map(fctx.GetResourcesByType("AWS::EC2::VPC"),
		func(resource *parser.Resource, _ int) ec2.VPC {
			return ec2.VPC{
				Metadata: resource.Metadata(),
				// CloudFormation does not provide direct management for the default VPC
				IsDefault:       types.BoolUnresolvable(resource.Metadata()),
				FlowLogsEnabled: types.Bool(vpcFlowLogs.Contains(resource.ID()), resource.Metadata()),
			}
		})
}

func getVpcGlowLogs(fctx parser.FileContext) set.Set[string] {
	ids := set.New[string]()
	for _, resource := range fctx.GetResourcesByType("AWS::EC2::FlowLog") {
		if resource.GetStringProperty("ResourceType").EqualTo("VPC") {
			ids.Append(resource.GetStringProperty("ResourceId").Value())
		}
	}
	return ids
}
