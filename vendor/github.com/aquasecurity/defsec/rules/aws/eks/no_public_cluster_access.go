package eks

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicClusterAccess = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0040",
		Provider:    providers.AWSProvider,
		Service:     "eks",
		ShortCode:   "no-public-cluster-access",
		Summary:     "EKS Clusters should have the public access disabled",
		Impact:      "EKS can be access from the internet",
		Resolution:  "Don't enable public access to EKS Clusters",
		Explanation: `EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource.`,
		Links: []string{
			"https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicClusterAccessGoodExamples,
			BadExamples:         terraformNoPublicClusterAccessBadExamples,
			Links:               terraformNoPublicClusterAccessLinks,
			RemediationMarkdown: terraformNoPublicClusterAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.EKS.Clusters {
			if cluster.PublicAccessEnabled.IsTrue() {
				results.Add(
					"Public cluster access is enabled.",
					cluster.PublicAccessEnabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
