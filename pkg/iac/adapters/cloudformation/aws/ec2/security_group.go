package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getSecurityGroups(ctx parser2.FileContext) (groups []ec2.SecurityGroup) {
	for _, r := range ctx.GetResourcesByType("AWS::EC2::SecurityGroup") {
		group := ec2.SecurityGroup{
			Metadata:     r.Metadata(),
			Description:  r.GetStringProperty("GroupDescription"),
			IngressRules: getIngressRules(r),
			EgressRules:  getEgressRules(r),
			IsDefault:    types.Bool(r.GetStringProperty("GroupName").EqualTo("default"), r.Metadata()),
			VPCID:        r.GetStringProperty("VpcId"),
		}

		groups = append(groups, group)
	}
	return groups
}

func getIngressRules(r *parser2.Resource) (sgRules []ec2.SecurityGroupRule) {
	if ingressProp := r.GetProperty("SecurityGroupIngress"); ingressProp.IsList() {
		for _, ingress := range ingressProp.AsList() {
			rule := ec2.SecurityGroupRule{
				Metadata:    ingress.Metadata(),
				Description: ingress.GetStringProperty("Description"),
				CIDRs:       nil,
			}
			v4Cidr := ingress.GetProperty("CidrIp")
			if v4Cidr.IsString() && v4Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v4Cidr.AsString(), v4Cidr.Metadata()))
			}
			v6Cidr := ingress.GetProperty("CidrIpv6")
			if v6Cidr.IsString() && v6Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v6Cidr.AsString(), v6Cidr.Metadata()))
			}

			sgRules = append(sgRules, rule)
		}
	}
	return sgRules
}

func getEgressRules(r *parser2.Resource) (sgRules []ec2.SecurityGroupRule) {
	if egressProp := r.GetProperty("SecurityGroupEgress"); egressProp.IsList() {
		for _, egress := range egressProp.AsList() {
			rule := ec2.SecurityGroupRule{
				Metadata:    egress.Metadata(),
				Description: egress.GetStringProperty("Description"),
			}
			v4Cidr := egress.GetProperty("CidrIp")
			if v4Cidr.IsString() && v4Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v4Cidr.AsString(), v4Cidr.Metadata()))
			}
			v6Cidr := egress.GetProperty("CidrIpv6")
			if v6Cidr.IsString() && v6Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v6Cidr.AsString(), v6Cidr.Metadata()))
			}

			sgRules = append(sgRules, rule)
		}
	}
	return sgRules
}
