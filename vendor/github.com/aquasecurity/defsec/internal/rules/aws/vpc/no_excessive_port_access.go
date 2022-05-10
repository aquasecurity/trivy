package vpc

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoExcessivePortAccess = rules.Register(
	scan.Rule{
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
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoExcessivePortAccessGoodExamples,
			BadExamples:         terraformNoExcessivePortAccessBadExamples,
			Links:               terraformNoExcessivePortAccessLinks,
			RemediationMarkdown: terraformNoExcessivePortAccessRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoExcessivePortAccessGoodExamples,
			BadExamples:         cloudFormationNoExcessivePortAccessBadExamples,
			Links:               cloudFormationNoExcessivePortAccessLinks,
			RemediationMarkdown: cloudFormationNoExcessivePortAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
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
