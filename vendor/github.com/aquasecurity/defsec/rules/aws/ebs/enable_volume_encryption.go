package ebs

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableVolumeEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0026",
		Provider:    providers.AWSProvider,
		Service:     "ebs",
		ShortCode:   "enable-volume-encryption",
		Summary:     "EBS volumes must be encrypted",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable encryption of EBS volumes",
		Explanation: `By enabling encryption on EBS volumes you protect the volume, the disk I/O and any derived snapshots from compromise if intercepted.`,
		Links:       []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableVolumeEncryptionGoodExamples,
			BadExamples:         terraformEnableVolumeEncryptionBadExamples,
			Links:               terraformEnableVolumeEncryptionLinks,
			RemediationMarkdown: terraformEnableVolumeEncryptionRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableVolumeEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableVolumeEncryptionBadExamples,
			Links:               cloudFormationEnableVolumeEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableVolumeEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, volume := range s.AWS.EBS.Volumes {
			if volume.IsUnmanaged() {
				continue
			}
			if volume.Encryption.Enabled.IsFalse() {
				results.Add(
					"EBS volume is not encrypted.",
					volume.Encryption.Enabled,
				)
			} else {
				results.AddPassed(&volume)
			}
		}
		return
	},
)
