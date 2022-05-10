package dns

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoRsaSha1 = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GCP-0012",
		Provider:    providers.GoogleProvider,
		Service:     "dns",
		ShortCode:   "no-rsa-sha1",
		Summary:     "Zone signing should not use RSA SHA1",
		Impact:      "Less secure encryption algorithm than others available",
		Resolution:  "Use RSA SHA512",
		Explanation: `RSA SHA1 is a weaker algorithm than SHA2-based algorithms such as RSA SHA256/512`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoRsaSha1GoodExamples,
			BadExamples:         terraformNoRsaSha1BadExamples,
			Links:               terraformNoRsaSha1Links,
			RemediationMarkdown: terraformNoRsaSha1RemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, zone := range s.Google.DNS.ManagedZones {
			if zone.IsUnmanaged() {
				continue
			}
			if zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm.EqualTo("rsasha1") {
				results.Add(
					"Zone KSK uses RSA SHA1 for signing.",
					zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm,
				)
			} else if zone.DNSSec.DefaultKeySpecs.ZoneSigningKey.Algorithm.EqualTo("rsasha1") {
				results.Add(
					"Zone ZSK uses RSA SHA1 for signing.",
					zone.DNSSec.DefaultKeySpecs.ZoneSigningKey.Algorithm,
				)
			} else {
				results.AddPassed(&zone)
			}
		}
		return
	},
)
