package elasticache

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAddDescriptionForSecurityGroup = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0049",
		Provider:   providers.AWSProvider,
		Service:    "elasticache",
		ShortCode:  "add-description-for-security-group",
		Summary:    "Missing description for security group/security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups and rules",
		Explanation: `Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SecurityGroups.Creating.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionForSecurityGroupGoodExamples,
			BadExamples:         terraformAddDescriptionForSecurityGroupBadExamples,
			Links:               terraformAddDescriptionForSecurityGroupLinks,
			RemediationMarkdown: terraformAddDescriptionForSecurityGroupRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationAddDescriptionForSecurityGroupGoodExamples,
			BadExamples:         cloudFormationAddDescriptionForSecurityGroupBadExamples,
			Links:               cloudFormationAddDescriptionForSecurityGroupLinks,
			RemediationMarkdown: cloudFormationAddDescriptionForSecurityGroupRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, sg := range s.AWS.ElastiCache.SecurityGroups {
			if sg.Description.IsEmpty() {
				results.Add(
					"Security group does not have a description.",
					sg.Description,
				)
			} else {
				results.AddPassed(&sg)
			}
		}
		return
	},
)
