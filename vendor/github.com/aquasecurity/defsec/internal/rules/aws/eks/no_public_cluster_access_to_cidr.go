package eks

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/internal/cidr"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var CheckNoPublicClusterAccessToCidr = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0041",
		Provider:    providers.AWSProvider,
		Service:     "eks",
		ShortCode:   "no-public-cluster-access-to-cidr",
		Summary:     "EKS cluster should not have open CIDR range for public access",
		Impact:      "EKS can be accessed from the internet",
		Resolution:  "Don't enable public access to EKS Clusters",
		Explanation: `EKS Clusters have public access cidrs set to 0.0.0.0/0 by default which is wide open to the internet. This should be explicitly set to a more specific private CIDR range`,
		Links: []string{
			"https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicClusterAccessToCidrGoodExamples,
			BadExamples:         terraformNoPublicClusterAccessToCidrBadExamples,
			Links:               terraformNoPublicClusterAccessToCidrLinks,
			RemediationMarkdown: terraformNoPublicClusterAccessToCidrRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.EKS.Clusters {
			if cluster.PublicAccessEnabled.IsFalse() {
				continue
			}
			for _, accessCidr := range cluster.PublicAccessCIDRs {
				if cidr.IsPublic(accessCidr.Value()) {
					results.Add(
						fmt.Sprintf("Cluster allows access from a public CIDR: %s.", accessCidr.Value()),
						accessCidr,
					)
				} else {
					results.AddPassed(&cluster)
				}
			}
		}
		return
	},
)
