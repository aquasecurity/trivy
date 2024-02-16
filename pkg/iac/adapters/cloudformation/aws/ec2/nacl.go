package ec2

import (
	"strconv"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getNetworkACLs(ctx parser.FileContext) (acls []ec2.NetworkACL) {
	for _, aclResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAcl") {
		acl := ec2.NetworkACL{
			Metadata:      aclResource.Metadata(),
			Rules:         getRules(aclResource.ID(), ctx),
			IsDefaultRule: iacTypes.BoolDefault(false, aclResource.Metadata()),
		}
		acls = append(acls, acl)
	}
	return acls
}

func getRules(id string, ctx parser.FileContext) (rules []ec2.NetworkACLRule) {
	for _, ruleResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAclEntry") {
		aclID := ruleResource.GetProperty("NetworkAclId")
		if aclID.IsString() && aclID.AsString() == id {

			rule := ec2.NetworkACLRule{
				Metadata: ruleResource.Metadata(),
				Type:     iacTypes.StringDefault(ec2.TypeIngress, ruleResource.Metadata()),
				Action:   iacTypes.StringDefault(ec2.ActionAllow, ruleResource.Metadata()),
				Protocol: iacTypes.String("-1", ruleResource.Metadata()),
				CIDRs:    nil,
			}

			if egressProperty := ruleResource.GetProperty("Egress"); egressProperty.IsBool() {
				if egressProperty.AsBool() {
					rule.Type = iacTypes.String(ec2.TypeEgress, egressProperty.Metadata())
				} else {
					rule.Type = iacTypes.String(ec2.TypeIngress, egressProperty.Metadata())
				}
			}

			if actionProperty := ruleResource.GetProperty("RuleAction"); actionProperty.IsString() {
				if actionProperty.AsString() == ec2.ActionAllow {
					rule.Action = iacTypes.String(ec2.ActionAllow, actionProperty.Metadata())
				} else {
					rule.Action = iacTypes.String(ec2.ActionDeny, actionProperty.Metadata())
				}
			}

			if protocolProperty := ruleResource.GetProperty("Protocol"); protocolProperty.IsInt() {
				protocol := protocolProperty.AsIntValue().Value()
				rule.Protocol = iacTypes.String(strconv.Itoa(protocol), protocolProperty.Metadata())
			}

			if ipv4Cidr := ruleResource.GetProperty("CidrBlock"); ipv4Cidr.IsString() {
				rule.CIDRs = append(rule.CIDRs, ipv4Cidr.AsStringValue())
			}

			if ipv6Cidr := ruleResource.GetProperty("Ipv6CidrBlock"); ipv6Cidr.IsString() {
				rule.CIDRs = append(rule.CIDRs, ipv6Cidr.AsStringValue())
			}

			rules = append(rules, rule)
		}
	}
	return rules
}
