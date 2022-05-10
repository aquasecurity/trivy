package redshift

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckUsesVPC = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0127",
		Provider:   providers.AWSProvider,
		Service:    "redshift",
		ShortCode:  "use-vpc",
		Summary:    "Redshift cluster should be deployed into a specific VPC",
		Impact:     "Redshift cluster does not benefit from VPC security if it is deployed in EC2 classic mode",
		Resolution: "Deploy Redshift cluster into a non default VPC",
		Explanation: `Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tennant.

In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.`,
		Links: []string{
			"https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseVpcGoodExamples,
			BadExamples:         terraformUseVpcBadExamples,
			Links:               terraformUseVpcLinks,
			RemediationMarkdown: terraformUseVpcRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationUseVpcGoodExamples,
			BadExamples:         cloudFormationUseVpcBadExamples,
			Links:               cloudFormationUseVpcLinks,
			RemediationMarkdown: cloudFormationUseVpcRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.Redshift.Clusters {
			if cluster.SubnetGroupName.IsEmpty() {
				results.Add(
					"Cluster is deployed outside of a VPC.",
					cluster.SubnetGroupName,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
