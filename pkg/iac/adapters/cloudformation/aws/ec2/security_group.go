package ec2

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getSecurityGroups(ctx parser.FileContext) []ec2.SecurityGroup {
	mGroups := make(map[string]ec2.SecurityGroup)

	for _, r := range ctx.GetResourcesByType("AWS::EC2::SecurityGroup") {
		group := ec2.SecurityGroup{
			Metadata:     r.Metadata(),
			Description:  r.GetStringProperty("GroupDescription"),
			IngressRules: getIngressRules(r),
			EgressRules:  getEgressRules(r),
			IsDefault:    types.Bool(r.GetStringProperty("GroupName").EqualTo("default"), r.Metadata()),
			VPCID:        r.GetStringProperty("VpcId"),
		}

		mGroups[r.ID()] = group
	}

	for _, r := range ctx.GetResourcesByType("AWS::EC2::SecurityGroupIngress") {
		groupID := r.GetProperty("GroupId").AsString()

		if group, ok := mGroups[groupID]; ok {
			group.IngressRules = append(group.IngressRules, adaptRule(r))
			mGroups[groupID] = group
		}
	}

	for _, r := range ctx.GetResourcesByType("AWS::EC2::SecurityGroupEgress") {
		groupID := r.GetProperty("GroupId").AsString()

		if group, ok := mGroups[groupID]; ok {
			group.EgressRules = append(group.EgressRules, adaptRule(r))
			mGroups[groupID] = group
		}
	}

	if len(mGroups) > 0 {
		return lo.Values(mGroups)
	}
	return nil
}

func getIngressRules(r *parser.Resource) (sgRules []ec2.SecurityGroupRule) {
	if ingressProp := r.GetProperty("SecurityGroupIngress"); ingressProp.IsList() {
		for _, ingress := range ingressProp.AsList() {
			sgRules = append(sgRules, adaptRule(ingress))
		}
	}

	return sgRules
}

func getEgressRules(r *parser.Resource) (sgRules []ec2.SecurityGroupRule) {
	if egressProp := r.GetProperty("SecurityGroupEgress"); egressProp.IsList() {
		for _, egress := range egressProp.AsList() {
			sgRules = append(sgRules, adaptRule(egress))
		}
	}
	return sgRules
}

func adaptRule(r interface {
	GetProperty(string) *parser.Property
	Metadata() types.Metadata
	GetStringProperty(string, ...string) types.StringValue
}) ec2.SecurityGroupRule {
	rule := ec2.SecurityGroupRule{
		Metadata:    r.Metadata(),
		Description: r.GetStringProperty("Description"),
		FromPort:    types.IntDefault(-1, r.Metadata()),
		ToPort:      types.IntDefault(-1, r.Metadata()),
	}

	v4Cidr := r.GetProperty("CidrIp")
	if v4Cidr.IsString() && v4Cidr.AsStringValue().IsNotEmpty() {
		rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v4Cidr.AsString(), v4Cidr.Metadata()))
	}
	v6Cidr := r.GetProperty("CidrIpv6")
	if v6Cidr.IsString() && v6Cidr.AsStringValue().IsNotEmpty() {
		rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v6Cidr.AsString(), v6Cidr.Metadata()))
	}

	fromPort := r.GetProperty("FromPort").ConvertTo(cftypes.Int)
	if fromPort.IsInt() {
		rule.FromPort = fromPort.AsIntValue()
	}

	toPort := r.GetProperty("ToPort").ConvertTo(cftypes.Int)
	if toPort.IsInt() {
		rule.ToPort = toPort.AsIntValue()
	}

	protocol := r.GetProperty("IpProtocol").ConvertTo(cftypes.String)
	if protocol.IsString() {
		rule.Protocol = protocol.AsStringValue()
	}

	return rule
}
