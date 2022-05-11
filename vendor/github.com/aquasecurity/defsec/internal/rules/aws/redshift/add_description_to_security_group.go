package redshift

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAddDescriptionToSecurityGroup = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0083",
		Provider:   providers.AWSProvider,
		Service:    "redshift",
		ShortCode:  "add-description-to-security-group",
		Summary:    "Missing description for security group/security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups and rules",
		Explanation: `Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationAddDescriptionToSecurityGroupGoodExamples,
			BadExamples:         cloudFormationAddDescriptionToSecurityGroupBadExamples,
			Links:               cloudFormationAddDescriptionToSecurityGroupLinks,
			RemediationMarkdown: cloudFormationAddDescriptionToSecurityGroupRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.Redshift.SecurityGroups {
			if group.Description.IsEmpty() {
				results.Add(
					"Security group has no description.",
					group.Description,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
