package vpc

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAddDescriptionToSecurityGroup = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0099",
		Provider:   providers.AWSProvider,
		Service:    "vpc",
		ShortCode:  "add-description-to-security-group",
		Summary:    "Missing description for security group.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups",
		Explanation: `Security groups should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToSecurityGroupGoodExamples,
			BadExamples:         terraformAddDescriptionToSecurityGroupBadExamples,
			Links:               terraformAddDescriptionToSecurityGroupLinks,
			RemediationMarkdown: terraformAddDescriptionToSecurityGroupRemediationMarkdown,
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
		for _, group := range s.AWS.VPC.SecurityGroups {
			if group.IsUnmanaged() {
				continue
			}
			if group.Description.IsEmpty() {
				results.Add(
					"Security group does not have a description.",
					group.Description,
				)
			} else if group.Description.EqualTo("Managed by Terraform") {
				results.Add(
					"Security group explicitly uses the default description.",
					group.Description,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
