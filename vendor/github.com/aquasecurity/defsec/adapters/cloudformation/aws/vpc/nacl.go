package vpc

import (
	"strconv"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"

	"github.com/aquasecurity/defsec/providers/aws/vpc"
)

func getNetworkACLs(ctx parser.FileContext) (acls []vpc.NetworkACL) {
	for _, aclResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAcl") {
		acl := vpc.NetworkACL{
			Metadata: aclResource.Metadata(),
			Rules:    getRules(aclResource.ID(), ctx),
		}
		acls = append(acls, acl)
	}
	return acls
}

func getRules(id string, ctx parser.FileContext) (rules []vpc.NetworkACLRule) {
	for _, ruleResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAclEntry") {
		aclID := ruleResource.GetProperty("NetworkAclId")
		if aclID.IsString() && aclID.AsString() == id {

			rule := vpc.NetworkACLRule{
				Metadata: ruleResource.Metadata(),
				Type:     types.StringDefault(vpc.TypeIngress, ruleResource.Metadata()),
				Action:   types.StringDefault(vpc.ActionAllow, ruleResource.Metadata()),
				Protocol: types.String("-1", ruleResource.Metadata()),
				CIDRs:    nil,
			}

			if egressProperty := ruleResource.GetProperty("Egress"); egressProperty.IsBool() {
				if egressProperty.AsBool() {
					rule.Type = types.String(vpc.TypeEgress, egressProperty.Metadata())
				} else {
					rule.Type = types.String(vpc.TypeIngress, egressProperty.Metadata())
				}
			}

			if actionProperty := ruleResource.GetProperty("RuleAction"); actionProperty.IsString() {
				if actionProperty.AsString() == vpc.ActionAllow {
					rule.Action = types.String(vpc.ActionAllow, actionProperty.Metadata())
				} else {
					rule.Action = types.String(vpc.ActionDeny, actionProperty.Metadata())
				}
			}

			if protocolProperty := ruleResource.GetProperty("Protocol"); protocolProperty.IsInt() {
				protocol := protocolProperty.AsIntValue().Value()
				rule.Protocol = types.String(strconv.Itoa(protocol), protocolProperty.Metadata())
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
