package vpc

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/vpc"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicIngress = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0105",
		Provider:    providers.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-public-ingress-acl",
		Summary:     "An ingress Network ACL rule allows specific ports from /0.",
		Impact:      "The ports are exposed for ingressing data to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressAclGoodExamples,
			BadExamples:         terraformNoPublicIngressAclBadExamples,
			Links:               terraformNoPublicIngressAclLinks,
			RemediationMarkdown: terraformNoPublicIngressAclRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressAclGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressAclBadExamples,
			Links:               cloudFormationNoPublicIngressAclLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressAclRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, acl := range s.AWS.VPC.NetworkACLs {
			for _, rule := range acl.Rules {
				if !rule.Type.EqualTo(vpc.TypeIngress) {
					continue
				}
				if !rule.Action.EqualTo(vpc.ActionAllow) {
					continue
				}
				var fail bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						fail = true
						results.Add(
							"Network ACL rule allows ingress from public internet.",
							block,
						)
					}
				}
				if !fail {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
