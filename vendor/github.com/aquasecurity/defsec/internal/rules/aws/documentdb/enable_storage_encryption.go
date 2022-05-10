package documentdb

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableStorageEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0021",
		Provider:    providers.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "enable-storage-encryption",
		Summary:     "DocumentDB storage must be encrypted",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable storage encryption",
		Explanation: `Encryption of the underlying storage used by DocumentDB ensures that if their is compromise of the disks, the data is still protected.`,
		Links:       []string{"https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html"},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableStorageEncryptionGoodExamples,
			BadExamples:         terraformEnableStorageEncryptionBadExamples,
			Links:               terraformEnableStorageEncryptionLinks,
			RemediationMarkdown: terraformEnableStorageEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableStorageEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableStorageEncryptionBadExamples,
			Links:               cloudFormationEnableStorageEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableStorageEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			if cluster.StorageEncrypted.IsFalse() {
				results.Add(
					"Cluster storage does not have encryption enabled.",
					cluster.StorageEncrypted,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
