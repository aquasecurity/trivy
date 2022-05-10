package vpc

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoExcessivePortAccess = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0102",
		Provider:    providers.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-excessive-port-access",
		Summary:     "An ingress Network ACL rule allows ALL ports.",
		Impact:      "All ports exposed for egressing data",
		Resolution:  "Set specific allowed ports",
		Explanation: `Ensure access to specific required ports is allowed, and nothing else.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoExcessivePortAccessGoodExamples,
			BadExamples:         terraformNoExcessivePortAccessBadExamples,
			Links:               terraformNoExcessivePortAccessLinks,
			RemediationMarkdown: terraformNoExcessivePortAccessRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoExcessivePortAccessGoodExamples,
			BadExamples:         cloudFormationNoExcessivePortAccessBadExamples,
			Links:               cloudFormationNoExcessivePortAccessLinks,
			RemediationMarkdown: cloudFormationNoExcessivePortAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, acl := range s.AWS.VPC.NetworkACLs {
			for _, rule := range acl.Rules {
				if rule.Protocol.EqualTo("-1") || rule.Protocol.EqualTo("all") {
					results.Add(
						"Network ACL rule allows access using ALL ports.",
						rule.Protocol,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
