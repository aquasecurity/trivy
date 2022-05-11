package rds

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicDbAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0082",
		Provider:    providers.AWSProvider,
		Service:     "rds",
		ShortCode:   "no-public-db-access",
		Summary:     "A database resource is marked as publicly accessible.",
		Impact:      "The database instance is publicly accessible",
		Resolution:  "Set the database to not be publicly accessible",
		Explanation: `Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicDbAccessGoodExamples,
			BadExamples:         terraformNoPublicDbAccessBadExamples,
			Links:               terraformNoPublicDbAccessLinks,
			RemediationMarkdown: terraformNoPublicDbAccessRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicDbAccessGoodExamples,
			BadExamples:         cloudFormationNoPublicDbAccessBadExamples,
			Links:               cloudFormationNoPublicDbAccessLinks,
			RemediationMarkdown: cloudFormationNoPublicDbAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			for _, instance := range cluster.Instances {
				if instance.PublicAccess.IsTrue() {
					results.Add(
						"Cluster instance is exposed publicly.",
						instance.PublicAccess,
					)
				} else {
					results.AddPassed(&instance)
				}
			}
		}
		for _, instance := range s.AWS.RDS.Instances {
			if instance.PublicAccess.IsTrue() {
				results.Add(
					"Instance is exposed publicly.",
					instance.PublicAccess,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
