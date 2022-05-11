package vpc

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicIngressSgr = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0107",
		Provider:    providers.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-public-ingress-sgr",
		Summary:     "An ingress security group rule allows traffic from /0.",
		Impact:      "Your port exposed to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressSgrGoodExamples,
			BadExamples:         terraformNoPublicIngressSgrBadExamples,
			Links:               terraformNoPublicIngressSgrLinks,
			RemediationMarkdown: terraformNoPublicIngressSgrRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressSgrGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressSgrBadExamples,
			Links:               cloudFormationNoPublicIngressSgrLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressSgrRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.VPC.SecurityGroups {
			for _, rule := range group.IngressRules {
				var failed bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						failed = true
						results.Add(
							"Security group rule allows ingress from public internet.",
							block,
						)
					}
				}
				if !failed {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
