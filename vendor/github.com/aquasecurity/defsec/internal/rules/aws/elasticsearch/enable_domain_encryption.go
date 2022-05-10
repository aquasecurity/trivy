package elasticsearch

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableDomainEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0048",
		Provider:    providers.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "enable-domain-encryption",
		Summary:     "Elasticsearch domain isn't encrypted at rest.",
		Impact:      "Data will be readable if compromised",
		Resolution:  "Enable ElasticSearch domain encryption",
		Explanation: `You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableDomainEncryptionGoodExamples,
			BadExamples:         terraformEnableDomainEncryptionBadExamples,
			Links:               terraformEnableDomainEncryptionLinks,
			RemediationMarkdown: terraformEnableDomainEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableDomainEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableDomainEncryptionBadExamples,
			Links:               cloudFormationEnableDomainEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableDomainEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.AtRestEncryption.Enabled.IsFalse() {
				results.Add(
					"Domain does not have at-rest encryption enabled.",
					domain.AtRestEncryption.Enabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
