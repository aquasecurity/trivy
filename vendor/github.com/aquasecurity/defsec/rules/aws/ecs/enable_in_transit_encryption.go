package ecs

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0035",
		Provider:    providers.AWSProvider,
		Service:     "ecs",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "ECS Task Definitions with EFS volumes should use in-transit encryption",
		Impact:      "Intercepted traffic to and from EFS may lead to data loss",
		Resolution:  "Enable in transit encryption when using efs",
		Explanation: `ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html",
			"https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableInTransitEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableInTransitEncryptionBadExamples,
			Links:               cloudFormationEnableInTransitEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, definition := range s.AWS.ECS.TaskDefinitions {
			for _, volume := range definition.Volumes {
				if volume.EFSVolumeConfiguration.TransitEncryptionEnabled.IsFalse() {
					results.Add(
						"Task definition includes a volume which does not have in-transit-encryption enabled.",
						volume.EFSVolumeConfiguration.TransitEncryptionEnabled,
					)
				} else {
					results.AddPassed(&volume)
				}
			}
		}
		return
	},
)
