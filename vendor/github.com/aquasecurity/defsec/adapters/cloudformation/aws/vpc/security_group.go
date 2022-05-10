package vpc

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/vpc"
)

func getSecurityGroups(ctx parser.FileContext) (groups []vpc.SecurityGroup) {
	for _, r := range ctx.GetResourceByType("AWS::EC2::SecurityGroup") {
		group := vpc.SecurityGroup{
			Metadata:     r.Metadata(),
			Description:  r.GetStringProperty("GroupDescription"),
			IngressRules: getIngressRules(r),
			EgressRules:  getEgressRules(r),
		}

		groups = append(groups, group)
	}
	return groups
}

func getIngressRules(r *parser.Resource) (sgRules []vpc.SecurityGroupRule) {
	if ingressProp := r.GetProperty("SecurityGroupIngress"); ingressProp.IsList() {
		for _, ingress := range ingressProp.AsList() {
			rule := vpc.SecurityGroupRule{
				Metadata: r.Metadata(),
			}
			rule.Description = ingress.GetStringProperty("Description")
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

func getEgressRules(r *parser.Resource) (sgRules []vpc.SecurityGroupRule) {
	if egressProp := r.GetProperty("SecurityGroupEgress"); egressProp.IsList() {
		for _, egress := range egressProp.AsList() {
			rule := vpc.SecurityGroupRule{
				Metadata: r.Metadata(),
			}
			rule.Description = egress.GetStringProperty("Description")
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
