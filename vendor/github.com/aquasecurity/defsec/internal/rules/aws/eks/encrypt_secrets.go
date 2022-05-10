package eks

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEncryptSecrets = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0039",
		Provider:    providers.AWSProvider,
		Service:     "eks",
		ShortCode:   "encrypt-secrets",
		Summary:     "EKS should have the encryption of secrets enabled",
		Impact:      "EKS secrets could be read if compromised",
		Resolution:  "Enable encryption of EKS secrets",
		Explanation: `EKS cluster resources should have the encryption_config block set with protection of the secrets resource.`,
		Links: []string{
			"https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEncryptSecretsGoodExamples,
			BadExamples:         terraformEncryptSecretsBadExamples,
			Links:               terraformEncryptSecretsLinks,
			RemediationMarkdown: terraformEncryptSecretsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEncryptSecretsGoodExamples,
			BadExamples:         cloudFormationEncryptSecretsBadExamples,
			Links:               cloudFormationEncryptSecretsLinks,
			RemediationMarkdown: cloudFormationEncryptSecretsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.EKS.Clusters {
			if cluster.Encryption.Secrets.IsFalse() {
				results.Add(
					"Cluster does not have secret encryption enabled.",
					cluster.Encryption.Secrets,
				)
			} else if cluster.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster encryption requires a KMS key ID, which is missing",
					cluster.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
