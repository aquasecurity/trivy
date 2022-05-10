package workspaces

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableDiskEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0109",
		Provider:    providers.AWSProvider,
		Service:     "workspaces",
		ShortCode:   "enable-disk-encryption",
		Summary:     "Root and user volumes on Workspaces should be encrypted",
		Impact:      "Data can be freely read if compromised",
		Resolution:  "Root and user volume encryption should be enabled",
		Explanation: `Workspace volumes for both user and root should be encrypted to protect the data stored on them.`,
		Links: []string{
			"https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableDiskEncryptionGoodExamples,
			BadExamples:         terraformEnableDiskEncryptionBadExamples,
			Links:               terraformEnableDiskEncryptionLinks,
			RemediationMarkdown: terraformEnableDiskEncryptionRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableDiskEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableDiskEncryptionBadExamples,
			Links:               cloudFormationEnableDiskEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableDiskEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, workspace := range s.AWS.WorkSpaces.WorkSpaces {
			var fail bool
			if workspace.RootVolume.Encryption.Enabled.IsFalse() {
				results.Add(
					"Root volume does not have encryption enabled.",
					workspace.RootVolume.Encryption.Enabled,
				)
				fail = true
			}
			if workspace.UserVolume.Encryption.Enabled.IsFalse() {
				results.Add(
					"User volume does not have encryption enabled.",
					workspace.UserVolume.Encryption.Enabled,
				)
				fail = true
			}
			if !fail {
				results.AddPassed(&workspace)
			}
		}
		return
	},
)
